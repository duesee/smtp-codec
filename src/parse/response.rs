use crate::{parse::command::Domain, types::EhloOkResp};
use abnf_core::streaming::{is_ALPHA, is_DIGIT, CRLF, SP};
use nom::multi::separated_list;
use nom::{
    branch::alt,
    bytes::streaming::{tag, take_while, take_while1, take_while_m_n},
    combinator::{map, map_res, opt, recognize},
    multi::many0,
    sequence::{delimited, preceded, tuple},
    IResult,
};

/// ehlo-ok-rsp = ( "250 " Domain [ SP ehlo-greet ] CRLF ) /
///               ( "250-" Domain [ SP ehlo-greet ] CRLF
///                 *( "250-" ehlo-line CRLF )
///                    "250 " ehlo-line CRLF )
///
/// Edit: collapsed ("250" SP) to ("250 ")
pub fn ehlo_ok_rsp(input: &[u8]) -> IResult<&[u8], EhloOkResp> {
    let parser = alt((
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
            |(_, domain, maybe_ehlo, _, lines, _, (keyword, params), _)| EhloOkResp {
                domain: domain.to_owned(),
                greet: maybe_ehlo.map(|ehlo| ehlo.to_owned()),
                lines: {
                    let mut lines = lines
                        .iter()
                        .map(|(keyword, params)| {
                            let params = params
                                .iter()
                                .map(|param| param.to_string())
                                .collect::<Vec<String>>();
                            (keyword.to_string(), params)
                        })
                        .collect::<Vec<(String, Vec<String>)>>();
                    lines.push((
                        keyword.to_string(),
                        params
                            .iter()
                            .map(|param| param.to_string())
                            .collect::<Vec<String>>(),
                    ));
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
        match byte {
            0..=9 | 11..=12 | 14..=127 => true,
            _ => false,
        }
    }

    map_res(take_while1(is_valid_character), std::str::from_utf8)(input)
}

/// ehlo-line = ehlo-keyword *( SP ehlo-param )
///
/// TODO: SMTP servers often respond with "AUTH=LOGIN PLAIN". Why?
pub fn ehlo_line(input: &[u8]) -> IResult<&[u8], (&str, Vec<&str>)> {
    let parser = tuple((
        map_res(ehlo_keyword, std::str::from_utf8),
        opt(preceded(
            alt((SP, tag("="))), // TODO: For Outlook?
            separated_list(SP, ehlo_param),
        )),
    ));

    let (remaining, (ehlo_keyword, ehlo_params)) = parser(input)?;

    Ok((remaining, (ehlo_keyword, ehlo_params.unwrap_or(vec![]))))
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
        match byte {
            33..=126 => true,
            _ => false,
        }
    }

    map_res(take_while1(is_valid_character), std::str::from_utf8)(input)
}

#[cfg(test)]
mod test {
    use super::*;

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
                    (
                        "AUTH".into(),
                        vec!["LOGIN".into(), "CRAM-MD5".into(), "PLAIN".into()]
                    ),
                    (
                        "AUTH".into(),
                        vec!["LOGIN".into(), "CRAM-MD5".into(), "PLAIN".into()]
                    ),
                    ("STARTTLS".into(), vec![]),
                    ("SIZE".into(), vec!["12345".into()]),
                    ("8BITMIME".into(), vec![]),
                ],
            }
        );
    }

    #[test]
    fn test_ehlo_line() {
        let (rem, (keyword, params)) = ehlo_line(b"SIZE 123456\r\n").unwrap();
        assert_eq!(rem, b"\r\n");
        assert_eq!(keyword, "SIZE");
        assert_eq!(params, &["123456"]);
    }
}
