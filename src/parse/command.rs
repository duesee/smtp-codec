use crate::{
    parse::{
        address::{General_address_literal, IPv4_address_literal, IPv6_address_literal},
        base64,
        imf::atom::is_atext,
    },
    types::Command,
};
use abnf_core::streaming::{is_ALPHA, is_DIGIT, CRLF, DQUOTE, SP};
use nom::{
    branch::alt,
    bytes::streaming::{tag, tag_no_case, take_while, take_while1, take_while_m_n},
    combinator::{opt, recognize},
    multi::many0,
    sequence::{delimited, preceded, tuple},
    IResult,
};

pub fn command(input: &[u8]) -> IResult<&[u8], Command> {
    let parser = alt((
        helo, ehlo, mail, rcpt, data, rset, vrfy, expn, help, noop, quit,
        starttls,   // Extensions
        auth_login, // https://interoperability.blob.core.windows.net/files/MS-XLOGIN/[MS-XLOGIN].pdf
        auth_plain, // RFC 4616
    ));

    let (remaining, parsed) = parser(input)?;

    Ok((remaining, parsed))
}

/// helo = "HELO" SP Domain CRLF
pub fn helo(input: &[u8]) -> IResult<&[u8], Command> {
    let parser = tuple((
        tag_no_case(b"HELO"),
        SP,
        alt((Domain, address_literal)), // address_literal alternative for Geary
        CRLF,
    ));

    let (remaining, (_, _, data, _)) = parser(input)?;

    Ok((remaining, Command::Helo(data.into())))
}

/// ehlo = "EHLO" SP ( Domain / address-literal ) CRLF
pub fn ehlo(input: &[u8]) -> IResult<&[u8], Command> {
    let parser = tuple((
        tag_no_case(b"EHLO"),
        SP,
        alt((Domain, address_literal)),
        CRLF,
    ));

    let (remaining, (_, _, data, _)) = parser(input)?;

    Ok((remaining, Command::Ehlo(data.into())))
}

/// mail = "MAIL FROM:" Reverse-path [SP Mail-parameters] CRLF
pub fn mail(input: &[u8]) -> IResult<&[u8], Command> {
    let parser = tuple((
        tag_no_case(b"MAIL FROM:"),
        opt(SP), // Out-of-Spec, but Outlook does it ...
        Reverse_path,
        opt(preceded(SP, Mail_parameters)),
        CRLF,
    ));

    let (remaining, (_, _, data, maybe_params, _)) = parser(input)?;

    Ok((
        remaining,
        Command::Mail {
            data: data.into(),
            params: maybe_params.map(|params| params.into()),
        },
    ))
}

/// rcpt = "RCPT TO:" ( "<Postmaster@" Domain ">" / "<Postmaster>" / Forward-path ) [SP Rcpt-parameters] CRLF
///
/// Note that, in a departure from the usual rules for
/// local-parts, the "Postmaster" string shown above is
/// treated as case-insensitive.
pub fn rcpt(input: &[u8]) -> IResult<&[u8], Command> {
    let parser = tuple((
        tag_no_case(b"RCPT TO:"),
        opt(SP), // Out-of-Spec, but Outlook does it ...
        alt((
            recognize(tuple((tag_no_case(b"<Postmaster@"), Domain, tag(b">")))),
            tag_no_case(b"<Postmaster>"),
            Forward_path,
        )),
        opt(preceded(SP, Rcpt_parameters)),
        CRLF,
    ));

    let (remaining, (_, _, data, maybe_params, _)) = parser(input)?;

    Ok((
        remaining,
        Command::Rcpt {
            data: data.into(),
            params: maybe_params.map(|params| params.into()),
        },
    ))
}

/// data = "DATA" CRLF
pub fn data(input: &[u8]) -> IResult<&[u8], Command> {
    let parser = tuple((tag_no_case(b"DATA"), CRLF));

    let (remaining, _) = parser(input)?;

    Ok((remaining, Command::Data))
}

/// rset = "RSET" CRLF
pub fn rset(input: &[u8]) -> IResult<&[u8], Command> {
    let parser = tuple((tag_no_case(b"RSET"), CRLF));

    let (remaining, _) = parser(input)?;

    Ok((remaining, Command::Rset))
}

/// vrfy = "VRFY" SP String CRLF
pub fn vrfy(input: &[u8]) -> IResult<&[u8], Command> {
    let parser = tuple((tag_no_case(b"VRFY"), SP, String, CRLF));

    let (remaining, (_, _, data, _)) = parser(input)?;

    Ok((remaining, Command::Vrfy(data.into())))
}

/// expn = "EXPN" SP String CRLF
pub fn expn(input: &[u8]) -> IResult<&[u8], Command> {
    let parser = tuple((tag_no_case(b"EXPN"), SP, String, CRLF));

    let (remaining, (_, _, data, _)) = parser(input)?;

    Ok((remaining, Command::Expn(data.into())))
}

/// help = "HELP" [ SP String ] CRLF
pub fn help(input: &[u8]) -> IResult<&[u8], Command> {
    let parser = tuple((tag_no_case(b"HELP"), opt(preceded(SP, String)), CRLF));

    let (remaining, (_, maybe_data, _)) = parser(input)?;

    Ok((remaining, Command::Help(maybe_data.map(|data| data.into()))))
}

/// noop = "NOOP" [ SP String ] CRLF
pub fn noop(input: &[u8]) -> IResult<&[u8], Command> {
    let parser = tuple((tag_no_case(b"NOOP"), opt(preceded(SP, String)), CRLF));

    let (remaining, (_, maybe_data, _)) = parser(input)?;

    Ok((remaining, Command::Noop(maybe_data.map(|data| data.into()))))
}

/// quit = "QUIT" CRLF
pub fn quit(input: &[u8]) -> IResult<&[u8], Command> {
    let parser = tuple((tag_no_case(b"QUIT"), CRLF));

    let (remaining, _) = parser(input)?;

    Ok((remaining, Command::Quit))
}

pub fn starttls(input: &[u8]) -> IResult<&[u8], Command> {
    let parser = tuple((tag_no_case(b"STARTTLS"), CRLF));

    let (remaining, _) = parser(input)?;

    Ok((remaining, Command::StartTLS))
}

/// https://interoperability.blob.core.windows.net/files/MS-XLOGIN/[MS-XLOGIN].pdf
///
/// username = 1*CHAR ; Base64-encoded username
/// password = 1*CHAR ; Base64-encoded password
///
/// auth_login_command = "AUTH LOGIN" [SP username] CRLF
///
/// auth_login_username_challenge = "334 VXNlcm5hbWU6" CRLF
/// auth_login_username_response  = username CRLF
/// auth_login_password_challenge = "334 UGFzc3dvcmQ6" CRLF
/// auth_login_password_response  = password CRLF
pub fn auth_login(input: &[u8]) -> IResult<&[u8], Command> {
    let parser = tuple((
        tag_no_case(b"AUTH"),
        SP,
        tag_no_case("LOGIN"),
        opt(preceded(SP, base64)),
        CRLF,
    ));

    let (remaining, (_, _, _, maybe_username_b64, _)) = parser(input)?;

    Ok((
        remaining,
        Command::AuthLogin(maybe_username_b64.map(|i| i.to_owned())),
    ))
}

pub fn auth_plain(input: &[u8]) -> IResult<&[u8], Command> {
    let parser = tuple((
        tag_no_case(b"AUTH"),
        SP,
        tag_no_case("PLAIN"),
        opt(preceded(SP, base64)),
        CRLF,
    ));

    let (remaining, (_, _, _, maybe_credentials_b64, _)) = parser(input)?;

    Ok((
        remaining,
        Command::AuthPlain(maybe_credentials_b64.map(|i| i.to_owned())),
    ))
}

// ----- 4.1.2.  Command Argument Syntax (RFC 5321) -----

/// Reverse-path = Path / "<>"
pub fn Reverse_path(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = alt((Path, tag(b"<>")));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// Forward-path = Path
pub fn Forward_path(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = Path;

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

// Path = "<" [ A-d-l ":" ] Mailbox ">"
pub fn Path(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = tuple((
        tag(b"<"),
        opt(tuple((A_d_l, tag(b":")))),
        Mailbox,
        tag(b">"),
    ));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// A-d-l = At-domain *( "," At-domain )
///          ; Note that this form, the so-called "source
///          ; route", MUST BE accepted, SHOULD NOT be
///          ; generated, and SHOULD be ignored.
pub fn A_d_l(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = tuple((At_domain, many0(tuple((tag(b","), At_domain)))));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// At-domain = "@" Domain
pub fn At_domain(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = tuple((tag(b"@"), Domain));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// Mail-parameters = esmtp-param *(SP esmtp-param)
pub fn Mail_parameters(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = tuple((esmtp_param, many0(tuple((SP, esmtp_param)))));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// Rcpt-parameters = esmtp-param *(SP esmtp-param)
pub fn Rcpt_parameters(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = tuple((esmtp_param, many0(tuple((SP, esmtp_param)))));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// esmtp-param = esmtp-keyword ["=" esmtp-value]
pub fn esmtp_param(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = tuple((esmtp_keyword, opt(tuple((tag(b"="), esmtp_value)))));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// esmtp-keyword = (ALPHA / DIGIT) *(ALPHA / DIGIT / "-")
pub fn esmtp_keyword(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = tuple((
        take_while_m_n(1, 1, |byte| is_ALPHA(byte) || is_DIGIT(byte)),
        take_while(|byte| is_ALPHA(byte) || is_DIGIT(byte) || byte == b'-'),
    ));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// Any CHAR excluding "=", SP, and control characters.
/// If this string is an email address, i.e., a Mailbox,
/// then the "xtext" syntax [32] SHOULD be used.
///
/// esmtp-value = 1*(%d33-60 / %d62-126)
pub fn esmtp_value(input: &[u8]) -> IResult<&[u8], &[u8]> {
    fn is_value_character(byte: u8) -> bool {
        match byte {
            33..=60 | 62..=126 => true,
            _ => false,
        }
    }

    take_while1(is_value_character)(input)
}

/// Keyword = Ldh-str
pub fn Keyword(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = Ldh_str;

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// Argument = Atom
pub fn Argument(input: &[u8]) -> IResult<&[u8], &[u8]> {
    Atom(input)
}

/// Domain = sub-domain *("." sub-domain)
pub fn Domain(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = tuple((sub_domain, many0(tuple((tag(b"."), sub_domain)))));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// sub-domain = Let-dig [Ldh-str]
pub fn sub_domain(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = tuple((take_while_m_n(1, 1, is_Let_dig), opt(Ldh_str)));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// Let-dig = ALPHA / DIGIT
pub fn is_Let_dig(byte: u8) -> bool {
    is_ALPHA(byte) || is_DIGIT(byte)
}

/// Ldh-str = *( ALPHA / DIGIT / "-" ) Let-dig
pub fn Ldh_str(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = many0(alt((
        take_while_m_n(1, 1, is_ALPHA),
        take_while_m_n(1, 1, is_DIGIT),
        recognize(tuple((tag(b"-"), take_while_m_n(1, 1, is_Let_dig)))),
    )));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// address-literal = "[" (
///                       IPv4-address-literal /
///                       IPv6-address-literal /
///                       General-address-literal
///                   ) "]"
///                     ; See Section 4.1.3
pub fn address_literal(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = delimited(
        tag(b"["),
        alt((
            IPv4_address_literal,
            IPv6_address_literal,
            General_address_literal,
        )),
        tag(b"]"),
    );

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// Mailbox = Local-part "@" ( Domain / address-literal )
pub fn Mailbox(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = tuple((Local_part, tag(b"@"), alt((Domain, address_literal))));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// Local-part = Dot-string / Quoted-string
///               ; MAY be case-sensitive
pub fn Local_part(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = alt((Dot_string, Quoted_string));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// Dot-string = Atom *("."  Atom)
pub fn Dot_string(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = tuple((Atom, many0(tuple((tag(b"."), Atom)))));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// Atom = 1*atext
pub fn Atom(input: &[u8]) -> IResult<&[u8], &[u8]> {
    take_while1(is_atext)(input)
}

/// Quoted-string = DQUOTE *QcontentSMTP DQUOTE
pub fn Quoted_string(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = delimited(DQUOTE, many0(QcontentSMTP), DQUOTE);

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// QcontentSMTP = qtextSMTP / quoted-pairSMTP
pub fn QcontentSMTP(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = alt((take_while_m_n(1, 1, is_qtextSMTP), quoted_pairSMTP));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// Backslash followed by any ASCII graphic (including itself) or SPace
///
/// quoted-pairSMTP = %d92 %d32-126
pub fn quoted_pairSMTP(input: &[u8]) -> IResult<&[u8], &[u8]> {
    fn is_ascii_bs_or_sp(byte: u8) -> bool {
        match byte {
            32..=126 => true,
            _ => false,
        }
    }

    let parser = tuple((tag("\\"), take_while_m_n(1, 1, is_ascii_bs_or_sp)));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// Within a quoted string, any ASCII graphic or space is permitted
/// without blackslash-quoting except double-quote and the backslash itself.
///
/// qtextSMTP = %d32-33 / %d35-91 / %d93-126
pub fn is_qtextSMTP(byte: u8) -> bool {
    match byte {
        32..=33 | 35..=91 | 93..=126 => true,
        _ => false,
    }
}

/// String = Atom / Quoted-string
pub fn String(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = alt((Atom, Quoted_string));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}
