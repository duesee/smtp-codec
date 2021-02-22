//! 4.2.  SMTP Replies (RFC 5321)

use crate::{
    parse::command::{address_literal, Domain},
    types::Greeting as GreetingType,
};
use abnf_core::streaming::{CRLF, SP};
use nom::{
    branch::alt,
    bytes::streaming::{tag, take_while1, take_while_m_n},
    combinator::{map, map_res, opt, recognize},
    multi::many0,
    sequence::{delimited, preceded, tuple},
    IResult,
};

/// Greeting = ( "220 " (Domain / address-literal) [ SP textstring ] CRLF ) /
///            ( "220-" (Domain / address-literal) [ SP textstring ] CRLF
///            *( "220-" [ textstring ] CRLF )
///            "220" [ SP textstring ] CRLF )
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
                    .unwrap_or("".to_string()),
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
                        .unwrap_or("\n".to_string());

                    for text in more_text {
                        let text = text
                            .map(|str| format!("{}\n", str))
                            .unwrap_or("\n".to_string());
                        res.push_str(&text);
                    }

                    let text = moar_text
                        .map(|str| format!("{}", str))
                        .unwrap_or("".to_string());
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
        match byte {
            9 | 32..=126 => true,
            _ => false,
        }
    }

    let (remaining, parsed) = map_res(take_while1(is_value), std::str::from_utf8)(input)?;

    Ok((remaining, parsed))
}

/// Reply-line = *( Reply-code "-" [ textstring ] CRLF )
///              Reply-code [ SP textstring ] CRLF
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
pub fn Reply_code(input: &[u8]) -> IResult<&[u8], &[u8]> {
    // FIXME: do not accept all codes.
    take_while_m_n(3, 3, nom::character::is_digit)(input)
}

#[cfg(test)]
mod test {
    use super::*;

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
}
