//! 4.1.3.  Address Literals (RFC 5321)

use crate::parse::command::Ldh_str;
use abnf_core::streaming::is_DIGIT;
use nom::{
    branch::alt,
    bytes::streaming::{tag, tag_no_case, take_while1, take_while_m_n},
    character::is_hex_digit,
    combinator::{opt, recognize},
    multi::{count, many_m_n},
    sequence::tuple,
    IResult,
};

/// IPv4-address-literal = Snum 3("."  Snum)
pub fn IPv4_address_literal(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = tuple((Snum, count(tuple((tag(b"."), Snum)), 3)));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// IPv6-address-literal = "IPv6:" IPv6-addr
pub fn IPv6_address_literal(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = tuple((tag_no_case(b"IPv6:"), IPv6_addr));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// General-address-literal = Standardized-tag ":" 1*dcontent
pub fn General_address_literal(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = tuple((Standardized_tag, tag(b":"), take_while1(is_dcontent)));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// Standardized-tag MUST be specified in a Standards-Track RFC and registered with IANA
///
/// Standardized-tag = Ldh-str
pub fn Standardized_tag(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = Ldh_str;

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// Printable US-ASCII excl. "[", "\", "]"
///
/// dcontent = %d33-90 / %d94-126
pub fn is_dcontent(byte: u8) -> bool {
    matches!(byte, 33..=90 | 94..=126)
}

/// Representing a decimal integer value in the range 0 through 255
///
/// Snum = 1*3DIGIT
pub fn Snum(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = take_while_m_n(1, 3, is_DIGIT);

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// IPv6-addr = IPv6-full / IPv6-comp / IPv6v4-full / IPv6v4-comp
pub fn IPv6_addr(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = alt((IPv6_full, IPv6_comp, IPv6v4_full, IPv6v4_comp));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// IPv6-hex = 1*4HEXDIG
pub fn IPv6_hex(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = take_while_m_n(1, 4, is_hex_digit);

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// IPv6-full = IPv6-hex 7(":" IPv6-hex)
pub fn IPv6_full(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = tuple((IPv6_hex, count(tuple((tag(b":"), IPv6_hex)), 7)));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// The "::" represents at least 2 16-bit groups of zeros.
/// No more than 6 groups in addition to the "::" may be present.
///
/// IPv6-comp = [IPv6-hex *5(":" IPv6-hex)] "::" [IPv6-hex *5(":" IPv6-hex)]
pub fn IPv6_comp(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = tuple((
        opt(tuple((
            IPv6_hex,
            many_m_n(0, 5, tuple((tag(b":"), IPv6_hex))),
        ))),
        tag(b"::"),
        opt(tuple((
            IPv6_hex,
            many_m_n(0, 5, tuple((tag(b":"), IPv6_hex))),
        ))),
    ));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// IPv6v4-full = IPv6-hex 5(":" IPv6-hex) ":" IPv4-address-literal
pub fn IPv6v4_full(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = tuple((
        IPv6_hex,
        count(tuple((tag(b":"), IPv6_hex)), 5),
        tag(b":"),
        IPv4_address_literal,
    ));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// The "::" represents at least 2 16-bit groups of zeros.
/// No more than 4 groups in addition to the "::" and IPv4-address-literal may be present.
///
/// IPv6v4-comp = [IPv6-hex *3(":" IPv6-hex)] "::"
///               [IPv6-hex *3(":" IPv6-hex) ":"]
///               IPv4-address-literal
pub fn IPv6v4_comp(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = tuple((
        opt(tuple((
            IPv6_hex,
            many_m_n(0, 3, tuple((tag(b":"), IPv6_hex))),
        ))),
        tag(b"::"),
        opt(tuple((
            IPv6_hex,
            many_m_n(0, 3, tuple((tag(b":"), IPv6_hex))),
            tag(b":"),
        ))),
        IPv4_address_literal,
    ));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}
