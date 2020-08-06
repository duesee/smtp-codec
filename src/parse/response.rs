use crate::parse::command::Domain;
use abnf_core::streaming::{is_ALPHA, is_DIGIT, CRLF, SP};
use nom::{
    branch::alt,
    bytes::streaming::{tag, take_while, take_while1, take_while_m_n},
    combinator::{opt, recognize},
    multi::many0,
    sequence::tuple,
    IResult,
};

/// ehlo-ok-rsp = ( "250" SP Domain [ SP ehlo-greet ] CRLF ) /
///               ( "250-" Domain [ SP ehlo-greet ] CRLF
///                 *( "250-" ehlo-line CRLF )
///                 "250" SP ehlo-line CRLF )
pub fn ehlo_ok_rsp(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = alt((
        recognize(tuple((
            tag(b"250"),
            SP,
            Domain,
            opt(tuple((SP, ehlo_greet))),
            CRLF,
        ))),
        recognize(tuple((
            tag(b"250-"),
            Domain,
            opt(tuple((SP, ehlo_greet))),
            CRLF,
            many0(tuple((tag(b"250-"), ehlo_line, CRLF))),
            tag(b"250"),
            SP,
            ehlo_line,
            CRLF,
        ))),
    ));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// String of any characters other than CR or LF.
///
/// ehlo-greet = 1*(%d0-9 / %d11-12 / %d14-127)
pub fn ehlo_greet(input: &[u8]) -> IResult<&[u8], &[u8]> {
    fn is_valid_character(byte: u8) -> bool {
        match byte {
            0..=9 | 11..=12 | 14..=127 => true,
            _ => false,
        }
    }

    take_while1(is_valid_character)(input)
}

/// ehlo-line = ehlo-keyword *( SP ehlo-param )
pub fn ehlo_line(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = tuple((ehlo_keyword, many0(tuple((SP, ehlo_param)))));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
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
pub fn ehlo_param(input: &[u8]) -> IResult<&[u8], &[u8]> {
    fn is_valid_character(byte: u8) -> bool {
        match byte {
            33..=126 => true,
            _ => false,
        }
    }

    take_while1(is_valid_character)(input)
}
