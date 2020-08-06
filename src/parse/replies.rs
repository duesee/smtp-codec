//! 4.2.  SMTP Replies (RFC 5321)

use crate::parse::command::{address_literal, Domain};
use abnf_core::streaming::{CRLF, SP};
use nom::{
    branch::alt,
    bytes::streaming::{tag, take_while1, take_while_m_n},
    combinator::{opt, recognize},
    multi::many0,
    sequence::tuple,
    IResult,
};

/// Greeting = ( "220 " (Domain / address-literal) [ SP textstring ] CRLF ) /
///            ( "220-" (Domain / address-literal) [ SP textstring ] CRLF
///            *( "220-" [ textstring ] CRLF )
///            "220" [ SP textstring ] CRLF )
pub fn Greeting(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = alt((
        recognize(tuple((
            tag(b"220 "),
            alt((Domain, address_literal)),
            opt(tuple((SP, textstring))),
            CRLF,
        ))),
        recognize(tuple((
            tag(b"220-"),
            alt((Domain, address_literal)),
            opt(tuple((SP, textstring))),
            CRLF,
            many0(tuple((tag(b"220-"), opt(textstring), CRLF))),
            tag(b"220"),
            opt(tuple((SP, textstring))),
            CRLF,
        ))),
    ));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// HT, SP, Printable US-ASCII
///
/// textstring = 1*(%d09 / %d32-126)
pub fn textstring(input: &[u8]) -> IResult<&[u8], &[u8]> {
    fn is_value(byte: u8) -> bool {
        match byte {
            9 | 32..=126 => true,
            _ => false,
        }
    }

    take_while1(is_value)(input)
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
