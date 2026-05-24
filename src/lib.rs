#[cfg(feature = "python-bindings")]
use pyo3::prelude::*;
use std::borrow::Cow;
use std::io;
use std::io::{Read, Write};
use std::str::FromStr;

/// The maximum size of message we will accept (for DoS-prevention reasons).
const PLAUSIBLE_LENGTH: u16 = 1024 * 32;
/// The IPA stream id for an osmocom stream.
const IPAC_PROTO_OSMO: u8 = 0xEE;
/// The Osmocom protocol identifier for the control protocol.
///
/// This is prepended to the payload of an osmocom stream.
const OSMOCOM_CONTROL_PROTOCOL_ID: u8 = 0x00;

/// An osmocom "IPA" framed message.
#[derive(PartialEq, Debug)]
struct IpaMessage {
    stream_id: u8,
    payload: Vec<u8>,
}

impl IpaMessage {
    /// Read a message from `stream`.
    fn read(stream: &mut impl Read) -> io::Result<Self> {
        // Header format: u16 length (network byte order) + u8 stream id
        let mut header: [u8; 3] = [0; 3];
        stream.read_exact(&mut header)?;

        let length = u16::from_be_bytes([header[0], header[1]]);
        let stream_id = header[2];

        if length > PLAUSIBLE_LENGTH {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "header length implausibly long",
            ));
        }

        let mut payload = vec![0u8; length as usize];
        stream.read_exact(&mut payload)?;

        Ok(Self { stream_id, payload })
    }

    /// Write this message to `stream`.
    fn write(&self, stream: &mut impl Write) -> io::Result<()> {
        let Ok(length): Result<u16, _> = self.payload.len().try_into() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "payload too big",
            ));
        };

        let length_be = length.to_be_bytes();

        // This is very inefficient in terms of write() calls, but meh.
        stream.write_all(&length_be)?;
        stream.write_all(&[self.stream_id])?;
        stream.write_all(&self.payload)?;

        Ok(())
    }
}

#[derive(Debug, PartialEq)]
enum ControlResponse {
    GetReply {
        id: usize,
        var: String,
        value: String,
    },
    SetReply {
        id: usize,
        var: String,
        value: String,
    },
    Error {
        id: usize,
        reason: String,
    },
    Trap {
        var: String,
        value: String,
    },
}

impl FromStr for ControlResponse {
    type Err = Cow<'static, str>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parse_id = |id: &str| -> Result<usize, Self::Err> {
            let Ok(id) = id.parse::<usize>() else {
                return Err(format!("malformed id value: {id}").into());
            };
            Ok(id)
        };

        match s.split_once(' ') {
            Some((kind @ "GET_REPLY" | kind @ "SET_REPLY", rest)) => {
                let Some((id, var, value)) = rest
                    .split_once(' ')
                    .and_then(|(a, rest)| rest.split_once(' ').map(|(b, rest)| (a, b, rest)))
                else {
                    return Err(format!("{kind} response had insufficient spaces").into());
                };
                let id = parse_id(id)?;

                Ok(if kind == "GET_REPLY" {
                    Self::GetReply {
                        id,
                        var: var.to_owned(),
                        value: value.to_owned(),
                    }
                } else {
                    Self::SetReply {
                        id,
                        var: var.to_owned(),
                        value: value.to_owned(),
                    }
                })
            }
            Some(("TRAP", rest)) => {
                let Some((var, val)) = rest.split_once(' ') else {
                    return Err("trap response had <2 fields".into());
                };

                Ok(Self::Trap {
                    var: var.to_owned(),
                    value: val.to_owned(),
                })
            }
            Some(("ERROR", rest)) => {
                let Some((id, reason)) = rest.split_once(' ') else {
                    return Err("error response had <2 fields".into());
                };
                let id = parse_id(id)?;

                Ok(Self::Error {
                    id,
                    reason: reason.to_owned(),
                })
            }
            Some((x, _)) => Err(format!("unknown response to message '{x}'").into()),
            None => Err("no spaces in control reply".into()),
        }
    }
}

/// A wrapper around a stream `S` that implements the Osmocom control protocol.
struct OsmoControl<S> {
    stream: S,
}

impl<S> OsmoControl<S>
where
    S: Read + Write,
{
    /// Send off a `payload` with the control framing.
    fn send(&mut self, payload: &str) -> io::Result<()> {
        let mut message = IpaMessage {
            stream_id: IPAC_PROTO_OSMO,
            payload: vec![OSMOCOM_CONTROL_PROTOCOL_ID],
        };

        message.payload.extend(payload.as_bytes());
        message.write(&mut self.stream)?;

        Ok(())
    }

    /// Get a reply from the stream.
    ///
    /// `discard_traps` will cause trap replies to be discarded.
    fn get_reply(&mut self, discard_traps: bool) -> io::Result<ControlResponse> {
        loop {
            let message = IpaMessage::read(&mut self.stream)?;
            if message.stream_id != IPAC_PROTO_OSMO
                || message.payload.get(0).copied() != Some(OSMOCOM_CONTROL_PROTOCOL_ID)
            {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "malformed IPA header received",
                ));
            }

            let Ok(payload) = str::from_utf8(&message.payload[1..]) else {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "osmocom response is not UTF-8",
                ));
            };

            let reply = ControlResponse::from_str(payload).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("parsing control response failed: {e}"),
                )
            })?;

            if discard_traps {
                if let ControlResponse::Trap { .. } = reply {
                    continue;
                }
            }

            return Ok(reply);
        }
    }
}

#[cfg(feature = "python-bindings")]
#[pymodule]
mod osmoapi {
    use crate::{ControlResponse, OsmoControl};
    use pyo3::create_exception;
    use pyo3::exceptions::{
        PyConnectionAbortedError, PyConnectionRefusedError, PyConnectionResetError, PyOSError,
        PyTimeoutError,
    };
    use pyo3::prelude::*;
    use std::io;
    use std::net::TcpStream;

    create_exception!(osmoapi, OsmocomProtocolError, pyo3::exceptions::PyException);
    create_exception!(osmoapi, OsmocomControlError, pyo3::exceptions::PyException);

    fn convert_error(e: io::Error) -> PyErr {
        use io::ErrorKind::*;

        let formatted = e.to_string();

        match e.kind() {
            ConnectionRefused => PyConnectionRefusedError::new_err(formatted).into(),
            ConnectionReset => PyConnectionResetError::new_err(formatted).into(),
            ConnectionAborted => PyConnectionAbortedError::new_err(formatted).into(),
            TimedOut => PyTimeoutError::new_err(formatted).into(),
            Other => OsmocomProtocolError::new_err(formatted).into(),
            _ => PyOSError::new_err(formatted).into(),
        }
    }

    #[pyclass(name = "OsmocomController")]
    pub struct OsmocomController {
        inner: OsmoControl<TcpStream>,
    }

    #[pymethods]
    impl OsmocomController {
        #[new]
        fn new(address: String) -> PyResult<Self> {
            let stream = TcpStream::connect(address).map_err(convert_error)?;

            Ok(Self {
                inner: OsmoControl { stream },
            })
        }

        fn get(&mut self, var: &str) -> PyResult<String> {
            let id: u32 = rand::random();

            self.inner
                .send(&format!("GET {id} {var}"))
                .map_err(convert_error)?;

            match self.inner.get_reply(true).map_err(convert_error)? {
                ControlResponse::GetReply {
                    id: reply_id,
                    var: reply_var,
                    value,
                } => {
                    if id as usize != reply_id || var != reply_var {
                        return Err(OsmocomProtocolError::new_err(format!(
                            "mismatched get_reply: asked for id {} var {}, got id {} var {}",
                            id, reply_id, reply_id, reply_var
                        )));
                    }

                    Ok(value)
                }
                ControlResponse::Error {
                    id: reply_id,
                    reason,
                } => {
                    if id as usize != reply_id {
                        return Err(OsmocomProtocolError::new_err(format!(
                            "mismatched get_reply: asked for id {}, got id {}",
                            id, reply_id
                        )));
                    }

                    Err(OsmocomControlError::new_err(reason))
                }
                other => Err(OsmocomProtocolError::new_err(format!(
                    "got unexpected reply to GET: {other:?}"
                ))),
            }
        }

        fn set(&mut self, var: &str, val: &str) -> PyResult<String> {
            let id: u32 = rand::random();

            self.inner
                .send(&format!("SET {id} {var} {val}"))
                .map_err(convert_error)?;

            match self.inner.get_reply(true).map_err(convert_error)? {
                ControlResponse::SetReply {
                    id: reply_id,
                    var: reply_var,
                    value,
                } => {
                    if id as usize != reply_id || var != reply_var {
                        return Err(OsmocomProtocolError::new_err(format!(
                            "mismatched set_reply: asked for id {} var {}, got id {} var {}",
                            id, reply_id, reply_id, reply_var
                        )));
                    }

                    Ok(value)
                }
                ControlResponse::Error {
                    id: reply_id,
                    reason,
                } => {
                    if id as usize != reply_id {
                        return Err(OsmocomProtocolError::new_err(format!(
                            "mismatched set_reply: asked for id {}, got id {}",
                            id, reply_id
                        )));
                    }

                    Err(OsmocomControlError::new_err(reason))
                }
                other => Err(OsmocomProtocolError::new_err(format!(
                    "got unexpected reply to SET: {other:?}"
                ))),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{ControlResponse, IpaMessage};
    use std::io::Cursor;
    use std::str::FromStr;

    #[test]
    fn ipa_roundtrip() {
        let message = IpaMessage {
            stream_id: 42,
            payload: vec![0xca, 0xfe, 0xba, 0xbe],
        };

        let mut wire = vec![];
        message.write(&mut wire).unwrap();

        assert_eq!(IpaMessage::read(&mut Cursor::new(&wire)).unwrap(), message);
    }

    #[test]
    fn replies() {
        assert_eq!(
            ControlResponse::from_str("GET_REPLY 42 zone honk").unwrap(),
            ControlResponse::GetReply {
                id: 42,
                var: "zone".to_string(),
                value: "honk".to_string(),
            }
        );

        assert_eq!(
            ControlResponse::from_str("SET_REPLY 42 zone honk").unwrap(),
            ControlResponse::SetReply {
                id: 42,
                var: "zone".to_string(),
                value: "honk".to_string(),
            }
        );

        assert_eq!(
            ControlResponse::from_str("SET_REPLY 42 zone honk with spaces whee").unwrap(),
            ControlResponse::SetReply {
                id: 42,
                var: "zone".to_string(),
                value: "honk with spaces whee".to_string(),
            }
        );

        assert_eq!(
            ControlResponse::from_str("ERROR 42 whoops mistake").unwrap(),
            ControlResponse::Error {
                id: 42,
                reason: "whoops mistake".to_string(),
            }
        );
    }
}
