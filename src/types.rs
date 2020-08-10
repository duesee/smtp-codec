use crate::escape;

#[derive(Clone, PartialEq, Eq)]
pub enum Command {
    Ehlo(Vec<u8>),
    Helo(Vec<u8>),
    Mail {
        data: Vec<u8>,
        params: Option<Vec<u8>>,
    },
    Rcpt {
        data: Vec<u8>,
        params: Option<Vec<u8>>,
    },
    Data,
    Rset,
    Vrfy(Vec<u8>),
    Expn(Vec<u8>),
    Help(Option<Vec<u8>>),
    Noop(Option<Vec<u8>>),
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
            Command::Ehlo(_) => "EHLO",
            Command::Helo(_) => "HELO",
            Command::Mail { .. } => "MAIL",
            Command::Rcpt { .. } => "RCPT",
            Command::Data => "DATA",
            Command::Rset => "RSET",
            Command::Vrfy(_) => "VRFY",
            Command::Expn(_) => "EXPN",
            Command::Help(_) => "HELP",
            Command::Noop(_) => "NOOP",
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

impl std::fmt::Debug for Command {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        use Command::*;

        match self {
            Ehlo(data) => write!(f, "Ehlo({})", escape(data)),
            Helo(data) => write!(f, "Helo({})", escape(data)),
            Mail {
                data: path,
                params: None,
            } => write!(f, "Mail({})", escape(path)),
            Mail {
                data: path,
                params: Some(params),
            } => write!(f, "Mail({}, {})", escape(path), escape(params)),
            Rcpt { data, params: None } => write!(f, "Rcpt({})", escape(data)),
            Rcpt {
                data,
                params: Some(params),
            } => write!(f, "Rcpt({}, {})", escape(data), escape(params)),
            Data => write!(f, "Data"),
            Rset => write!(f, "Rset"),
            Vrfy(data) => write!(f, "Vrfy({})", escape(data)),
            Expn(data) => write!(f, "Expn({})", escape(data)),
            Help(None) => write!(f, "Help"),
            Help(Some(data)) => write!(f, "Help({})", escape(data)),
            Noop(None) => write!(f, "Noop"),
            Noop(Some(data)) => write!(f, "Noop({})", escape(data)),
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
