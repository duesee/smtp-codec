use crate::{
    parse::{address::address_literal, number, Domain},
    types::{AuthMechanism, Capability, EhloOkResp, Greeting as GreetingType},
};
use abnf_core::streaming::{is_ALPHA, is_DIGIT, CRLF, SP};
use nom::{
    branch::alt,
    bytes::streaming::{tag, tag_no_case, take_while, take_while1, take_while_m_n},
    combinator::{map, map_res, opt, recognize, value},
    multi::{many0, separated_list0},
    sequence::{delimited, preceded, tuple},
    IResult,
};

/// Greeting = ( "220 " (Domain / address-literal) [ SP textstring ] CRLF ) /
///            ( "220-" (Domain / address-literal) [ SP textstring ] CRLF
///           *( "220-" [ textstring ] CRLF )
///              "220" [ SP textstring ] CRLF )
pub fn Greeting(input: &[u8]) -> IResult<&[u8], GreetingType> {
    let mut parser = alt((
        map(
            tuple((
                tag(b"220 "),
                alt((Domain, address_literal)),
                opt(preceded(SP, textstring)),
                CRLF,
            )),
            |(_, domain, maybe_text, _)| GreetingType {
                domain: domain.to_owned(),
                text: maybe_text
                    .map(|str| str.to_string())
                    .unwrap_or_else(|| "".to_string()),
            },
        ),
        map(
            tuple((
                tag(b"220-"),
                alt((Domain, address_literal)),
                opt(preceded(SP, textstring)),
                CRLF,
                many0(delimited(tag(b"220-"), opt(textstring), CRLF)),
                tag(b"220"),
                opt(preceded(SP, textstring)),
                CRLF,
            )),
            |(_, domain, maybe_text, _, more_text, _, moar_text, _)| GreetingType {
                domain: domain.to_owned(),
                text: {
                    let mut res = maybe_text
                        .map(|str| format!("{}\n", str))
                        .unwrap_or_else(|| "\n".to_string());

                    for text in more_text {
                        let text = text
                            .map(|str| format!("{}\n", str))
                            .unwrap_or_else(|| "\n".to_string());
                        res.push_str(&text);
                    }

                    let text = moar_text
                        .map(|str| str.to_string())
                        .unwrap_or_else(|| "".to_string());
                    res.push_str(&text);

                    res
                },
            },
        ),
    ));

    let (remaining, parsed) = parser(input)?;

    Ok((remaining, parsed))
}

/// HT, SP, Printable US-ASCII
///
/// textstring = 1*(%d09 / %d32-126)
pub fn textstring(input: &[u8]) -> IResult<&[u8], &str> {
    fn is_value(byte: u8) -> bool {
        matches!(byte, 9 | 32..=126)
    }

    let (remaining, parsed) = map_res(take_while1(is_value), std::str::from_utf8)(input)?;

    Ok((remaining, parsed))
}

// -------------------------------------------------------------------------------------------------

/// ehlo-ok-rsp = ( "250 " Domain [ SP ehlo-greet ] CRLF ) /
///               ( "250-" Domain [ SP ehlo-greet ] CRLF
///              *( "250-" ehlo-line CRLF )
///                 "250 " ehlo-line CRLF )
///
/// Edit: collapsed ("250" SP) to ("250 ")
pub fn ehlo_ok_rsp(input: &[u8]) -> IResult<&[u8], EhloOkResp> {
    let mut parser = alt((
        map(
            tuple((tag(b"250 "), Domain, opt(preceded(SP, ehlo_greet)), CRLF)),
            |(_, domain, maybe_ehlo, _)| EhloOkResp {
                domain: domain.to_owned(),
                greet: maybe_ehlo.map(|ehlo| ehlo.to_owned()),
                lines: Vec::new(),
            },
        ),
        map(
            tuple((
                tag(b"250-"),
                Domain,
                opt(preceded(SP, ehlo_greet)),
                CRLF,
                many0(delimited(tag(b"250-"), ehlo_line, CRLF)),
                tag(b"250 "),
                ehlo_line,
                CRLF,
            )),
            |(_, domain, maybe_ehlo, _, mut lines, _, line, _)| EhloOkResp {
                domain: domain.to_owned(),
                greet: maybe_ehlo.map(|ehlo| ehlo.to_owned()),
                lines: {
                    lines.push(line);
                    lines
                },
            },
        ),
    ));

    let (remaining, parsed) = parser(input)?;

    Ok((remaining, parsed))
}

/// String of any characters other than CR or LF.
///
/// ehlo-greet = 1*(%d0-9 / %d11-12 / %d14-127)
pub fn ehlo_greet(input: &[u8]) -> IResult<&[u8], &str> {
    fn is_valid_character(byte: u8) -> bool {
        matches!(byte, 0..=9 | 11..=12 | 14..=127)
    }

    map_res(take_while1(is_valid_character), std::str::from_utf8)(input)
}

/// ehlo-line = ehlo-keyword *( SP ehlo-param )
///
/// TODO: SMTP servers often respond with "AUTH=LOGIN PLAIN". Why?
pub fn ehlo_line(input: &[u8]) -> IResult<&[u8], Capability> {
    let auth = tuple((
        tag_no_case("AUTH"),
        alt((tag_no_case(" "), tag_no_case("="))),
        separated_list0(SP, auth_mechanism),
    ));

    let other = tuple((
        map_res(ehlo_keyword, std::str::from_utf8),
        opt(preceded(
            alt((SP, tag("="))), // TODO: For Outlook?
            separated_list0(SP, ehlo_param),
        )),
    ));

    alt((
        value(Capability::EXPN, tag_no_case("EXPN")),
        value(Capability::Help, tag_no_case("HELP")),
        value(Capability::EightBitMIME, tag_no_case("8BITMIME")),
        map(preceded(tag_no_case("SIZE "), number), Capability::Size),
        value(Capability::Chunking, tag_no_case("CHUNKING")),
        value(Capability::BinaryMIME, tag_no_case("BINARYMIME")),
        value(Capability::Checkpoint, tag_no_case("CHECKPOINT")),
        value(Capability::DeliverBy, tag_no_case("DELIVERBY")),
        value(Capability::Pipelining, tag_no_case("PIPELINING")),
        value(Capability::DSN, tag_no_case("DSN")),
        value(Capability::ETRN, tag_no_case("ETRN")),
        value(
            Capability::EnhancedStatusCodes,
            tag_no_case("ENHANCEDSTATUSCODES"),
        ),
        value(Capability::StartTLS, tag_no_case("STARTTLS")),
        // FIXME: NO-SOLICITING
        value(Capability::MTRK, tag_no_case("MTRK")),
        value(Capability::ATRN, tag_no_case("ATRN")),
        map(auth, |(_, _, mechanisms)| Capability::Auth(mechanisms)),
        value(Capability::BURL, tag_no_case("BURL")),
        // FIXME: FUTURERELEASE
        // FIXME: CONPERM
        // FIXME: CONNEG
        value(Capability::SMTPUTF8, tag_no_case("SMTPUTF8")),
        // FIXME: MT-PRIORITY
        value(Capability::RRVS, tag_no_case("RRVS")),
        value(Capability::RequireTLS, tag_no_case("REQUIRETLS")),
        map(other, |(keyword, params)| Capability::Other {
            keyword: keyword.into(),
            params: params
                .map(|v| v.iter().map(|s| s.to_string()).collect())
                .unwrap_or_default(),
        }),
    ))(input)
}

/// Additional syntax of ehlo-params depends on ehlo-keyword
///
/// ehlo-keyword = (ALPHA / DIGIT) *(ALPHA / DIGIT / "-")
pub fn ehlo_keyword(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = tuple((
        take_while_m_n(1, 1, |byte| is_ALPHA(byte) || is_DIGIT(byte)),
        take_while(|byte| is_ALPHA(byte) || is_DIGIT(byte) || byte == b'-'),
    ));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// Any CHAR excluding <SP> and all control characters
/// (US-ASCII 0-31 and 127 inclusive)
///
/// ehlo-param = 1*(%d33-126)
pub fn ehlo_param(input: &[u8]) -> IResult<&[u8], &str> {
    fn is_valid_character(byte: u8) -> bool {
        matches!(byte, 33..=126)
    }

    map_res(take_while1(is_valid_character), std::str::from_utf8)(input)
}

pub fn auth_mechanism(input: &[u8]) -> IResult<&[u8], AuthMechanism> {
    alt((
        value(AuthMechanism::Login, tag_no_case("LOGIN")),
        value(AuthMechanism::Plain, tag_no_case("PLAIN")),
        value(AuthMechanism::CramMD5, tag_no_case("CRAM-MD5")),
        value(AuthMechanism::CramSHA1, tag_no_case("CRAM-SHA1")),
        value(AuthMechanism::DigestMD5, tag_no_case("DIGEST-MD5")),
        value(AuthMechanism::ScramMD5, tag_no_case("SCRAM-MD5")),
        value(AuthMechanism::GSSAPI, tag_no_case("GSSAPI")),
        value(AuthMechanism::NTLM, tag_no_case("NTLM")),
        map(ehlo_param, |param| AuthMechanism::Other(param.to_string())),
    ))(input)
}

// -------------------------------------------------------------------------------------------------

/// Reply-line = *( Reply-code "-" [ textstring ] CRLF )
///                 Reply-code [ SP textstring ] CRLF
pub fn Reply_line(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = tuple((
        many0(tuple((Reply_code, tag(b"-"), opt(textstring), CRLF))),
        Reply_code,
        opt(tuple((SP, textstring))),
        CRLF,
    ));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// Reply-code = %x32-35 %x30-35 %x30-39
///
///   2345
/// 012345
/// 0123456789
pub fn Reply_code(input: &[u8]) -> IResult<&[u8], u16> {
    // FIXME: do not accept all codes.
    map_res(
        map_res(
            take_while_m_n(3, 3, nom::character::is_digit),
            std::str::from_utf8,
        ),
        |s| u16::from_str_radix(s, 10),
    )(input)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::types::AuthMechanism;

    #[test]
    fn test_Greeting() {
        let greeting = b"220-example.org ESMTP Fake 4.93 #2 Thu, 16 Jul 2020 07:30:16 -0400\r\n\
220-We do not authorize the use of this system to transport unsolicited,\r\n\
220 and/or bulk e-mail.\r\n";

        let (rem, out) = Greeting(greeting).unwrap();
        assert_eq!(rem, b"");
        assert_eq!(
            out,
            GreetingType {
                domain: "example.org".into(),
                text: "ESMTP Fake 4.93 #2 Thu, 16 Jul 2020 07:30:16 -0400\n\
We do not authorize the use of this system to transport unsolicited,\n\
and/or bulk e-mail."
                    .into(),
            }
        )
    }

    #[test]
    fn test_ehlo_ok_rsp() {
        let (rem, out) = ehlo_ok_rsp(
            b"250-example.org hello\r\n\
250-AUTH LOGIN CRAM-MD5 PLAIN\r\n\
250-AUTH=LOGIN CRAM-MD5 PLAIN\r\n\
250-STARTTLS\r\n\
250-SIZE 12345\r\n\
250 8BITMIME\r\n",
        )
        .unwrap();
        assert_eq!(rem, b"");
        assert_eq!(
            out,
            EhloOkResp {
                domain: "example.org".into(),
                greet: Some("hello".into()),
                lines: vec![
                    Capability::Auth(vec![
                        AuthMechanism::Login,
                        AuthMechanism::CramMD5,
                        AuthMechanism::Plain
                    ]),
                    Capability::Auth(vec![
                        AuthMechanism::Login,
                        AuthMechanism::CramMD5,
                        AuthMechanism::Plain
                    ]),
                    Capability::StartTLS,
                    Capability::Size(12345),
                    Capability::EightBitMIME,
                ],
            }
        );
    }

    #[test]
    fn test_ehlo_line() {
        let (rem, capability) = ehlo_line(b"SIZE 123456\r\n").unwrap();
        assert_eq!(rem, b"\r\n");
        assert_eq!(capability, Capability::Size(123456));
    }
}
