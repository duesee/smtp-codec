use std::io::Write;

#[cfg(feature = "serdex")]
use serde::{Deserialize, Serialize};

use crate::utils::escape_quoted;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    Ehlo {
        domain_or_address: DomainOrAddress,
    },
    Helo {
        domain_or_address: DomainOrAddress,
    },
    Mail {
        reverse_path: String,
        parameters: Vec<Parameter>,
    },
    Rcpt {
        forward_path: String,
        parameters: Vec<Parameter>,
    },
    Data,
    Rset,
    /// This command asks the receiver to confirm that the argument
    /// identifies a user or mailbox.  If it is a user name, information is
    /// returned as specified in Section 3.5.
    ///
    /// This command has no effect on the reverse-path buffer, the forward-
    /// path buffer, or the mail data buffer.
    Vrfy {
        user_or_mailbox: AtomOrQuoted,
    },
    /// This command asks the receiver to confirm that the argument
    /// identifies a mailing list, and if so, to return the membership of
    /// that list.  If the command is successful, a reply is returned
    /// containing information as described in Section 3.5.  This reply will
    /// have multiple lines except in the trivial case of a one-member list.
    ///
    /// This command has no effect on the reverse-path buffer, the forward-
    /// path buffer, or the mail data buffer, and it may be issued at any
    /// time.
    Expn {
        mailing_list: AtomOrQuoted,
    },
    /// This command causes the server to send helpful information to the
    /// client.  The command MAY take an argument (e.g., any command name)
    /// and return more specific information as a response.
    ///
    /// SMTP servers SHOULD support HELP without arguments and MAY support it
    /// with arguments.
    ///
    /// This command has no effect on the reverse-path buffer, the forward-
    /// path buffer, or the mail data buffer, and it may be issued at any
    /// time.
    Help {
        argument: Option<AtomOrQuoted>,
    },
    /// This command does not affect any parameters or previously entered
    /// commands.  It specifies no action other than that the receiver send a
    /// "250 OK" reply.
    ///
    ///  If a parameter string is specified, servers SHOULD ignore it.
    ///
    /// This command has no effect on the reverse-path buffer, the forward-
    /// path buffer, or the mail data buffer, and it may be issued at any
    /// time.
    Noop {
        argument: Option<AtomOrQuoted>,
    },
    /// This command specifies that the receiver MUST send a "221 OK" reply,
    /// and then close the transmission channel.
    ///
    /// The receiver MUST NOT intentionally close the transmission channel
    /// until it receives and replies to a QUIT command (even if there was an
    /// error).  The sender MUST NOT intentionally close the transmission
    /// channel until it sends a QUIT command, and it SHOULD wait until it
    /// receives the reply (even if there was an error response to a previous
    /// command).  If the connection is closed prematurely due to violations
    /// of the above or system or network failure, the server MUST cancel any
    /// pending transaction, but not undo any previously completed
    /// transaction, and generally MUST act as if the command or transaction
    /// in progress had received a temporary error (i.e., a 4yz response).
    ///
    /// The QUIT command may be issued at any time.  Any current uncompleted
    /// mail transaction will be aborted.
    Quit,
    // Extensions
    StartTLS,
    // AUTH LOGIN
    AuthLogin(Option<String>),
    // AUTH PLAIN
    AuthPlain(Option<String>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DomainOrAddress {
    Domain(String),
    Address(String),
}

impl DomainOrAddress {
    pub fn serialize(&self, writer: &mut impl Write) -> std::io::Result<()> {
        match self {
            DomainOrAddress::Domain(domain) => write!(writer, "{}", domain),
            DomainOrAddress::Address(address) => write!(writer, "[{}]", address),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Parameter {
    /// Message size declaration [RFC1870]
    Size(u32),
    Other {
        keyword: String,
        value: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AtomOrQuoted {
    Atom(String),
    Quoted(String),
}

impl Command {
    pub fn name(&self) -> &'static str {
        match self {
            Command::Ehlo { .. } => "EHLO",
            Command::Helo { .. } => "HELO",
            Command::Mail { .. } => "MAIL",
            Command::Rcpt { .. } => "RCPT",
            Command::Data => "DATA",
            Command::Rset => "RSET",
            Command::Vrfy { .. } => "VRFY",
            Command::Expn { .. } => "EXPN",
            Command::Help { .. } => "HELP",
            Command::Noop { .. } => "NOOP",
            Command::Quit => "QUIT",
            // Extensions
            Command::StartTLS => "STARTTLS",
            // TODO: SMTP AUTH LOGIN
            Command::AuthLogin(_) => "AUTHLOGIN",
            // TODO: SMTP AUTH PLAIN
            Command::AuthPlain(_) => "AUTHPLAIN",
        }
    }

    pub fn serialize(&self, writer: &mut impl Write) -> std::io::Result<()> {
        use Command::*;

        match self {
            // helo = "HELO" SP Domain CRLF
            Helo { domain_or_address } => {
                writer.write_all(b"HELO ")?;
                domain_or_address.serialize(writer)?;
            }
            // ehlo = "EHLO" SP ( Domain / address-literal ) CRLF
            Ehlo { domain_or_address } => {
                writer.write_all(b"EHLO ")?;
                domain_or_address.serialize(writer)?;
            }
            // mail = "MAIL FROM:" Reverse-path [SP Mail-parameters] CRLF
            Mail {
                reverse_path,
                parameters,
            } => {
                writer.write_all(b"MAIL FROM:<")?;
                writer.write_all(reverse_path.as_bytes())?;
                writer.write_all(b">")?;

                for parameter in parameters {
                    writer.write_all(b" ")?;
                    parameter.serialize(writer)?;
                }
            }
            // rcpt = "RCPT TO:" ( "<Postmaster@" Domain ">" / "<Postmaster>" / Forward-path ) [SP Rcpt-parameters] CRLF
            Rcpt {
                forward_path,
                parameters,
            } => {
                writer.write_all(b"RCPT TO:<")?;
                writer.write_all(forward_path.as_bytes())?;
                writer.write_all(b">")?;

                for parameter in parameters {
                    writer.write_all(b" ")?;
                    parameter.serialize(writer)?;
                }
            }
            // data = "DATA" CRLF
            Data => writer.write_all(b"DATA")?,
            // rset = "RSET" CRLF
            Rset => writer.write_all(b"RSET")?,
            // vrfy = "VRFY" SP String CRLF
            Vrfy { user_or_mailbox } => {
                writer.write_all(b"VRFY ")?;
                user_or_mailbox.serialize(writer)?;
            }
            // expn = "EXPN" SP String CRLF
            Expn { mailing_list } => {
                writer.write_all(b"EXPN ")?;
                mailing_list.serialize(writer)?;
            }
            // help = "HELP" [ SP String ] CRLF
            Help { argument: None } => writer.write_all(b"HELP")?,
            Help {
                argument: Some(data),
            } => {
                writer.write_all(b"HELP ")?;
                data.serialize(writer)?;
            }
            // noop = "NOOP" [ SP String ] CRLF
            Noop { argument: None } => writer.write_all(b"NOOP")?,
            Noop {
                argument: Some(data),
            } => {
                writer.write_all(b"NOOP ")?;
                data.serialize(writer)?;
            }
            // quit = "QUIT" CRLF
            Quit => writer.write_all(b"QUIT")?,
            // ----- Extensions -----
            // starttls = "STARTTLS" CRLF
            StartTLS => writer.write_all(b"STARTTLS")?,
            // auth_login_command = "AUTH LOGIN" [SP username] CRLF
            AuthLogin(None) => {
                writer.write_all(b"AUTH LOGIN")?;
            }
            AuthLogin(Some(data)) => {
                writer.write_all(b"AUTH LOGIN ")?;
                writer.write_all(data.as_bytes())?;
            }
            // auth_plain_command = "AUTH PLAIN" [SP base64] CRLF
            AuthPlain(None) => {
                writer.write_all(b"AUTH PLAIN")?;
            }
            AuthPlain(Some(data)) => {
                writer.write_all(b"AUTH PLAIN ")?;
                writer.write_all(data.as_bytes())?;
            }
        }

        write!(writer, "\r\n")
    }
}

impl Parameter {
    pub fn serialize(&self, writer: &mut impl Write) -> std::io::Result<()> {
        match self {
            Parameter::Size(size) => {
                write!(writer, "SIZE={}", size)?;
            }
            Parameter::Other { keyword, value } => {
                writer.write_all(keyword.as_bytes())?;

                if let Some(ref value) = value {
                    writer.write_all(b"=")?;
                    writer.write_all(value.as_bytes())?;
                }
            }
        };

        Ok(())
    }
}

impl AtomOrQuoted {
    pub fn serialize(&self, writer: &mut impl Write) -> std::io::Result<()> {
        match self {
            AtomOrQuoted::Atom(atom) => {
                writer.write_all(atom.as_bytes())?;
            }
            AtomOrQuoted::Quoted(quoted) => {
                writer.write_all(b"\"")?;
                writer.write_all(escape_quoted(quoted).as_bytes())?;
                writer.write_all(b"\"")?;
            }
        }

        Ok(())
    }
}

// -------------------------------------------------------------------------------------------------

#[cfg_attr(feature = "serdex", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Response {
    Greeting {
        domain: String,
        text: String,
    },
    Ehlo {
        domain: String,
        greet: Option<String>,
        capabilities: Vec<Capability>,
    },
    Other {
        code: u16,
        text: String,
    },
}

impl Response {
    pub fn greeting<D, T>(domain: D, text: T) -> Response
    where
        D: Into<String>,
        T: Into<String>,
    {
        Response::Greeting {
            domain: domain.into(),
            text: text.into(),
        }
    }

    pub fn ehlo<D, G>(domain: D, greet: Option<G>, capabilities: Vec<Capability>) -> Response
    where
        D: Into<String>,
        G: Into<String>,
    {
        Response::Ehlo {
            domain: domain.into(),
            greet: greet.map(Into::into),
            capabilities,
        }
    }

    pub fn other<T>(code: u16, text: T) -> Response
    where
        T: Into<String>,
    {
        Response::Other {
            code,
            text: text.into(),
        }
    }

    pub fn serialize(&self, writer: &mut impl Write) -> std::io::Result<()> {
        match self {
            Response::Greeting { domain, text } => {
                let lines = text.lines().collect::<Vec<_>>();

                if let Some((first, tail)) = lines.split_first() {
                    if let Some((last, head)) = tail.split_last() {
                        write!(writer, "220-{} {}\r\n", domain, first)?;

                        for line in head {
                            write!(writer, "220-{}\r\n", line)?;
                        }

                        write!(writer, "220 {}\r\n", last)?;
                    } else {
                        write!(writer, "220 {} {}\r\n", domain, first)?;
                    }
                } else {
                    write!(writer, "220 {}\r\n", domain)?;
                }
            }
            Response::Ehlo {
                domain,
                greet,
                capabilities,
            } => {
                let greet = match greet {
                    Some(greet) => format!(" {}", greet),
                    None => "".to_string(),
                };

                if let Some((tail, head)) = capabilities.split_last() {
                    writer.write_all(format!("250-{}{}\r\n", domain, greet).as_bytes())?;

                    for capability in head {
                        writer.write_all(b"250-")?;
                        capability.serialize(writer)?;
                        writer.write_all(b"\r\n")?;
                    }

                    writer.write_all(b"250 ")?;
                    tail.serialize(writer)?;
                    writer.write_all(b"\r\n")?;
                } else {
                    writer.write_all(format!("250 {}{}\r\n", domain, greet).as_bytes())?;
                }
            }
            Response::Other { code, text } => {
                let lines = text.lines().collect::<Vec<_>>();

                if let Some((last, head)) = lines.split_last() {
                    for line in head {
                        write!(writer, "{}-{}\r\n", code, line)?;
                    }

                    write!(writer, "{} {}\r\n", code, last)?;
                } else {
                    write!(writer, "{}\r\n", code)?;
                }
            }
        }

        Ok(())
    }
}

// -------------------------------------------------------------------------------------------------

#[cfg_attr(feature = "serdex", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Capability {
    // Send as mail [RFC821]
    // The description of SEND was updated by [RFC1123] and then its actual use was deprecated in [RFC2821]
    // SEND,

    // Send as mail or to terminal [RFC821]
    // The description of SOML was updated by [RFC1123] and then its actual use was deprecated in [RFC2821]
    // SOML,

    // Send as mail and to terminal [RFC821]
    // The description of SAML was updated by [RFC1123] and then its actual use was deprecated in [RFC2821]
    // SAML,

    // Interchange the client and server roles [RFC821]
    // The actual use of TURN was deprecated in [RFC2821]
    // TURN,

    // SMTP Responsible Submitter [RFC4405]
    // Deprecated by [https://datatracker.ietf.org/doc/status-change-change-sender-id-to-historic].
    // SUBMITTER,

    // Internationalized email address [RFC5336]
    // Experimental; deprecated in [RFC6531].
    // UTF8SMTP,

    // ---------------------------------------------------------------------------------------------
    /// Verbose [Eric Allman]
    // VERB,

    /// One message transaction only [Eric Allman]
    // ONEX,

    // ---------------------------------------------------------------------------------------------

    /// Expand the mailing list [RFC821]
    /// Command description updated by [RFC5321]
    EXPN,
    /// Supply helpful information [RFC821]
    /// Command description updated by [RFC5321]
    Help,

    /// SMTP and Submit transport of 8bit MIME content [RFC6152]
    EightBitMIME,

    /// Message size declaration [RFC1870]
    Size(u32),

    /// Chunking [RFC3030]
    Chunking,

    /// Binary MIME [RFC3030]
    BinaryMIME,

    /// Checkpoint/Restart [RFC1845]
    Checkpoint,

    /// Deliver By [RFC2852]
    DeliverBy,

    /// Command Pipelining [RFC2920]
    Pipelining,

    /// Delivery Status Notification [RFC3461]
    DSN,

    /// Extended Turn [RFC1985]
    /// SMTP [RFC5321] only. Not for use on Submit port 587.
    ETRN,

    /// Enhanced Status Codes [RFC2034]
    EnhancedStatusCodes,

    /// Start TLS [RFC3207]
    StartTLS,

    /// Notification of no soliciting [RFC3865]
    // NoSoliciting,

    /// Message Tracking [RFC3885]
    MTRK,

    /// Authenticated TURN [RFC2645]
    /// SMTP [RFC5321] only. Not for use on Submit port 587.
    ATRN,

    /// Authentication [RFC4954]
    Auth(Vec<AuthMechanism>),

    /// Remote Content [RFC4468]
    /// Submit [RFC6409] only. Not for use with SMTP on port 25.
    BURL,

    /// Future Message Release [RFC4865]
    // FutureRelease,

    /// Content Conversion Permission [RFC4141]
    // ConPerm,

    /// Content Conversion Negotiation [RFC4141]
    // ConNeg,

    /// Internationalized email address [RFC6531]
    SMTPUTF8,

    /// Priority Message Handling [RFC6710]
    // MTPRIORITY,

    /// Require Recipient Valid Since [RFC7293]
    RRVS,

    /// Require TLS [RFC8689]
    RequireTLS,

    // Observed ...
    // TIME,
    // XACK,
    // VERP,
    // VRFY,
    /// Other
    Other {
        keyword: String,
        params: Vec<String>,
    },
}

impl Capability {
    pub fn serialize(&self, writer: &mut impl Write) -> std::io::Result<()> {
        match self {
            Capability::EXPN => writer.write_all(b"EXPN"),
            Capability::Help => writer.write_all(b"HELP"),
            Capability::EightBitMIME => writer.write_all(b"8BITMIME"),
            Capability::Size(number) => writer.write_all(format!("SIZE {}", number).as_bytes()),
            Capability::Chunking => writer.write_all(b"CHUNKING"),
            Capability::BinaryMIME => writer.write_all(b"BINARYMIME"),
            Capability::Checkpoint => writer.write_all(b"CHECKPOINT"),
            Capability::DeliverBy => writer.write_all(b"DELIVERBY"),
            Capability::Pipelining => writer.write_all(b"PIPELINING"),
            Capability::DSN => writer.write_all(b"DSN"),
            Capability::ETRN => writer.write_all(b"ETRN"),
            Capability::EnhancedStatusCodes => writer.write_all(b"ENHANCEDSTATUSCODES"),
            Capability::StartTLS => writer.write_all(b"STARTTLS"),
            Capability::MTRK => writer.write_all(b"MTRK"),
            Capability::ATRN => writer.write_all(b"ATRN"),
            Capability::Auth(mechanisms) => {
                if let Some((tail, head)) = mechanisms.split_last() {
                    writer.write_all(b"AUTH ")?;

                    for mechanism in head {
                        mechanism.serialize(writer)?;
                        writer.write_all(b" ")?;
                    }

                    tail.serialize(writer)
                } else {
                    writer.write_all(b"AUTH")
                }
            }
            Capability::BURL => writer.write_all(b"BURL"),
            Capability::SMTPUTF8 => writer.write_all(b"SMTPUTF8"),
            Capability::RRVS => writer.write_all(b"RRVS"),
            Capability::RequireTLS => writer.write_all(b"REQUIRETLS"),
            Capability::Other { keyword, params } => {
                if let Some((tail, head)) = params.split_last() {
                    writer.write_all(keyword.as_bytes())?;
                    writer.write_all(b" ")?;

                    for param in head {
                        writer.write_all(param.as_bytes())?;
                        writer.write_all(b" ")?;
                    }

                    writer.write_all(tail.as_bytes())
                } else {
                    writer.write_all(keyword.as_bytes())
                }
            }
        }
    }
}

#[cfg_attr(feature = "serdex", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthMechanism {
    Plain,
    Login,
    GSSAPI,

    CramMD5,
    CramSHA1,
    ScramMD5,
    DigestMD5,
    NTLM,

    Other(String),
}

impl AuthMechanism {
    pub fn serialize(&self, writer: &mut impl Write) -> std::io::Result<()> {
        match self {
            AuthMechanism::Plain => writer.write_all(b"PLAIN"),
            AuthMechanism::Login => writer.write_all(b"LOGIN"),
            AuthMechanism::GSSAPI => writer.write_all(b"GSSAPI"),

            AuthMechanism::CramMD5 => writer.write_all(b"CRAM-MD5"),
            AuthMechanism::CramSHA1 => writer.write_all(b"CRAM-SHA1"),
            AuthMechanism::ScramMD5 => writer.write_all(b"SCRAM-MD5"),
            AuthMechanism::DigestMD5 => writer.write_all(b"DIGEST-MD5"),
            AuthMechanism::NTLM => writer.write_all(b"NTLM"),

            AuthMechanism::Other(other) => writer.write_all(other.as_bytes()),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::types::{Capability, Response};

    #[test]
    fn test_serialize_greeting() {
        let tests = &[
            (
                Response::Greeting {
                    domain: "example.org".into(),
                    text: "".into(),
                },
                b"220 example.org\r\n".as_ref(),
            ),
            (
                Response::Greeting {
                    domain: "example.org".into(),
                    text: "A".into(),
                },
                b"220 example.org A\r\n".as_ref(),
            ),
            (
                Response::Greeting {
                    domain: "example.org".into(),
                    text: "A\nB".into(),
                },
                b"220-example.org A\r\n220 B\r\n".as_ref(),
            ),
            (
                Response::Greeting {
                    domain: "example.org".into(),
                    text: "A\nB\nC".into(),
                },
                b"220-example.org A\r\n220-B\r\n220 C\r\n".as_ref(),
            ),
        ];

        for (test, expected) in tests.iter() {
            let mut got = Vec::new();
            test.serialize(&mut got).unwrap();
            assert_eq!(expected, &got);
        }
    }

    #[test]
    fn test_serialize_ehlo() {
        let tests = &[
            (
                Response::Ehlo {
                    domain: "example.org".into(),
                    greet: None,
                    capabilities: vec![],
                },
                b"250 example.org\r\n".as_ref(),
            ),
            (
                Response::Ehlo {
                    domain: "example.org".into(),
                    greet: Some("...".into()),
                    capabilities: vec![],
                },
                b"250 example.org ...\r\n".as_ref(),
            ),
            (
                Response::Ehlo {
                    domain: "example.org".into(),
                    greet: Some("...".into()),
                    capabilities: vec![Capability::StartTLS],
                },
                b"250-example.org ...\r\n250 STARTTLS\r\n".as_ref(),
            ),
            (
                Response::Ehlo {
                    domain: "example.org".into(),
                    greet: Some("...".into()),
                    capabilities: vec![Capability::StartTLS, Capability::Size(12345)],
                },
                b"250-example.org ...\r\n250-STARTTLS\r\n250 SIZE 12345\r\n".as_ref(),
            ),
        ];

        for (test, expected) in tests.iter() {
            let mut got = Vec::new();
            test.serialize(&mut got).unwrap();
            assert_eq!(expected, &got);
        }
    }

    #[test]
    fn test_serialize_other() {
        let tests = &[
            (
                Response::Other {
                    code: 333,
                    text: "".into(),
                },
                b"333\r\n".as_ref(),
            ),
            (
                Response::Other {
                    code: 333,
                    text: "A".into(),
                },
                b"333 A\r\n".as_ref(),
            ),
            (
                Response::Other {
                    code: 333,
                    text: "A\nB".into(),
                },
                b"333-A\r\n333 B\r\n".as_ref(),
            ),
        ];

        for (test, expected) in tests.iter() {
            let mut got = Vec::new();
            test.serialize(&mut got).unwrap();
            assert_eq!(expected, &got);
        }
    }
}
