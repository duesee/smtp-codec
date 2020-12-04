use crate::escape;
use std::io::Write;

#[derive(Clone, PartialEq, Eq)]
pub enum Command {
    Ehlo {
        fqdn_or_address_literal: Vec<u8>,
    },
    Helo {
        fqdn_or_address_literal: Vec<u8>,
    },
    Mail {
        reverse_path: Vec<u8>,
        parameters: Option<Vec<u8>>,
    },
    Rcpt {
        forward_path: Vec<u8>,
        parameters: Option<Vec<u8>>,
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
        user_or_mailbox: Vec<u8>,
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
        mailing_list: Vec<u8>,
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
        argument: Option<Vec<u8>>,
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
        argument: Option<Vec<u8>>,
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
}

// FIXME: try to derive(Debug) instead
impl std::fmt::Debug for Command {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        use Command::*;

        match self {
            Ehlo {
                fqdn_or_address_literal,
            } => write!(f, "Ehlo({})", escape(fqdn_or_address_literal)),
            Helo {
                fqdn_or_address_literal,
            } => write!(f, "Helo({})", escape(fqdn_or_address_literal)),
            Mail {
                reverse_path: path,
                parameters: None,
            } => write!(f, "Mail({})", escape(path)),
            Mail {
                reverse_path: path,
                parameters: Some(params),
            } => write!(f, "Mail({}, {})", escape(path), escape(params)),
            Rcpt {
                forward_path: data,
                parameters: None,
            } => write!(f, "Rcpt({})", escape(data)),
            Rcpt {
                forward_path: data,
                parameters: Some(params),
            } => write!(f, "Rcpt({}, {})", escape(data), escape(params)),
            Data => write!(f, "Data"),
            Rset => write!(f, "Rset"),
            Vrfy { user_or_mailbox } => write!(f, "Vrfy({})", escape(user_or_mailbox)),
            Expn { mailing_list } => write!(f, "Expn({})", escape(mailing_list)),
            Help { argument: None } => write!(f, "Help"),
            Help {
                argument: Some(data),
            } => write!(f, "Help({})", escape(data)),
            Noop { argument: None } => write!(f, "Noop"),
            Noop {
                argument: Some(data),
            } => write!(f, "Noop({})", escape(data)),
            Quit => write!(f, "Quit"),
            // Extensions
            StartTLS => write!(f, "StartTLS"),
            // TODO: SMTP Auth
            AuthLogin(data) => write!(f, "AuthLogin({:?})", data),
            // TODO: SMTP Auth
            AuthPlain(data) => write!(f, "AuthPlain({:?})", data),
        }
    }
}

impl Command {
    pub fn serialize(&self, writer: &mut impl Write) -> std::io::Result<()> {
        use Command::*;

        match self {
            // helo = "HELO" SP Domain CRLF
            Helo {
                fqdn_or_address_literal,
            } => {
                writer.write_all(b"HELO ")?;
                writer.write_all(fqdn_or_address_literal)?;
            }
            // ehlo = "EHLO" SP ( Domain / address-literal ) CRLF
            Ehlo {
                fqdn_or_address_literal,
            } => {
                writer.write_all(b"EHLO ")?;
                writer.write_all(fqdn_or_address_literal)?;
            }
            // mail = "MAIL FROM:" Reverse-path [SP Mail-parameters] CRLF
            Mail {
                reverse_path,
                parameters: None,
            } => {
                writer.write_all(b"MAIL FROM:<")?;
                writer.write_all(reverse_path)?;
                writer.write_all(b">")?;
            }
            Mail {
                reverse_path,
                parameters: Some(parameters),
            } => {
                writer.write_all(b"MAIL FROM:<")?;
                writer.write_all(reverse_path)?;
                writer.write_all(b"> ")?;
                writer.write_all(parameters)?;
            }
            // rcpt = "RCPT TO:" ( "<Postmaster@" Domain ">" / "<Postmaster>" / Forward-path ) [SP Rcpt-parameters] CRLF
            Rcpt {
                forward_path,
                parameters: None,
            } => {
                writer.write_all(b"RCPT TO:<")?;
                writer.write_all(forward_path)?;
                writer.write_all(b">")?;
            }
            Rcpt {
                forward_path,
                parameters: Some(parameters),
            } => {
                writer.write_all(b"RCPT TO:<")?;
                writer.write_all(forward_path)?;
                writer.write_all(b"> ")?;
                writer.write_all(parameters)?;
            }
            // data = "DATA" CRLF
            Data => writer.write_all(b"DATA")?,
            // rset = "RSET" CRLF
            Rset => writer.write_all(b"RSET")?,
            // vrfy = "VRFY" SP String CRLF
            Vrfy { user_or_mailbox } => {
                writer.write_all(b"VRFY ")?;
                writer.write_all(user_or_mailbox)?;
            }
            // expn = "EXPN" SP String CRLF
            Expn { mailing_list } => {
                writer.write_all(b"EXPN ")?;
                writer.write_all(mailing_list)?;
            }
            // help = "HELP" [ SP String ] CRLF
            Help { argument: None } => writer.write_all(b"HELP")?,
            Help {
                argument: Some(data),
            } => {
                writer.write_all(b"HELP ")?;
                writer.write_all(data)?;
            }
            // noop = "NOOP" [ SP String ] CRLF
            Noop { argument: None } => writer.write_all(b"NOOP")?,
            Noop {
                argument: Some(data),
            } => {
                writer.write_all(b"NOOP ")?;
                writer.write_all(data)?;
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Greeting {
    pub domain: String,
    // TODO: Vec<Option<String>> would be closer to the SMTP ABNF.
    // What is wrong with you, SMTP?
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EhloOkResp {
    pub domain: String,
    pub greet: Option<String>,
    pub lines: Vec<EhloLine>,
}

pub type EhloLine = (String, Vec<String>);
