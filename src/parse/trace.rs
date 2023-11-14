/// 4.4.  Trace Information (RFC 5321)
use abnf_core::streaming::CRLF;
use nom::{
    branch::alt,
    bytes::streaming::{tag, tag_no_case},
    combinator::{map_res, opt, recognize},
    multi::many1,
    sequence::tuple,
    IResult,
};

use crate::parse::{
    address::address_literal,
    atom,
    command::{mailbox, path, reverse_path},
    domain,
    imf::{
        datetime::date_time,
        folding_ws_and_comment::{cfws, fws},
        identification::msg_id,
    },
    string,
};

/// Return-path-line = "Return-Path:" FWS Reverse-path <CRLF>
pub fn return_path_line(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = tuple((tag_no_case(b"Return-Path:"), fws, reverse_path, CRLF));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// Time-stamp-line = "Received:" FWS Stamp <CRLF>
pub fn time_stamp_line(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = tuple((tag_no_case(b"Received:"), fws, stamp, CRLF));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// Stamp = From-domain By-domain Opt-info [cfws] ";" FWS date-time
///
/// Caution: Where "date-time" is as defined in RFC 5322 [4]
///          but the "obs-" forms, especially two-digit
///          years, are prohibited in SMTP and MUST NOT be used.
pub fn stamp(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = tuple((
        from_domain,
        by_domain,
        opt_info,
        opt(cfws),
        tag(b";"),
        fws,
        date_time,
    ));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// From-domain = "FROM" FWS Extended-Domain
pub fn from_domain(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = tuple((tag_no_case(b"FROM"), fws, extended_domain));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// By-domain = CFWS "BY" FWS Extended-Domain
pub fn by_domain(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = tuple((cfws, tag_no_case(b"BY"), fws, extended_domain));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// Extended-Domain = Domain /
///                   ( Domain FWS "(" TCP-info ")" ) /
///                   ( address-literal FWS "(" TCP-info ")" )
pub fn extended_domain(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = alt((
        recognize(domain),
        recognize(tuple((domain, fws, tag(b"("), tcp_info, tag(b")")))),
        recognize(tuple((
            address_literal,
            fws,
            tag(b"("),
            tcp_info,
            tag(b")"),
        ))),
    ));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// Information derived by server from TCP connection not client EHLO.
///
/// TCP-info = address-literal / ( Domain FWS address-literal )
pub fn tcp_info(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = alt((
        recognize(address_literal),
        recognize(tuple((domain, fws, address_literal))),
    ));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// Opt-info = [Via] [With] [ID] [For] [Additional-Registered-Clauses]
pub fn opt_info(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = tuple((
        opt(via),
        opt(with),
        opt(id),
        opt(r#for),
        opt(additional_registered_clauses),
    ));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// Via = CFWS "VIA" FWS Link
pub fn via(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = tuple((cfws, tag_no_case(b"VIA"), fws, link));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// With = CFWS "WITH" FWS Protocol
pub fn with(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = tuple((cfws, tag_no_case(b"WITH"), fws, protocol));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// ID = CFWS "ID" FWS ( Atom / msg-id )
///       ; msg-id is defined in RFC 5322 [4]
pub fn id(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = tuple((
        cfws,
        tag_no_case(b"ID"),
        fws,
        recognize(alt((recognize(atom), msg_id))),
    ));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// For = CFWS "FOR" FWS ( Path / Mailbox )
pub fn r#for(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = tuple((
        cfws,
        tag_no_case(b"FOR"),
        fws,
        alt((recognize(path), mailbox)),
    ));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// Additional standard clauses may be added in this location by future standards and registration with
/// IANA.  SMTP servers SHOULD NOT use unregistered names.  See Section 8.
///
/// Additional-Registered-Clauses = CFWS Atom FWS String
pub fn additional_registered_clauses(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = many1(tuple((cfws, atom, fws, string)));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// Link = "TCP" / Addtl-Link
pub fn link(input: &[u8]) -> IResult<&[u8], &str> {
    alt((map_res(tag_no_case("TCP"), std::str::from_utf8), addtl_link))(input)
}

/// Additional standard names for links are registered with the Internet Assigned Numbers
/// Authority (IANA).  "Via" is primarily of value with non-Internet transports.  SMTP servers
/// SHOULD NOT use unregistered names.
///
/// Addtl-Link = Atom
pub fn addtl_link(input: &[u8]) -> IResult<&[u8], &str> {
    atom(input)
}

/// Protocol = "ESMTP" / "SMTP" / Attdl-Protocol
pub fn protocol(input: &[u8]) -> IResult<&[u8], &str> {
    alt((
        map_res(tag_no_case(b"ESMTP"), std::str::from_utf8),
        map_res(tag_no_case(b"SMTP"), std::str::from_utf8),
        attdl_protocol,
    ))(input)
}

/// Additional standard names for protocols are registered with the Internet Assigned Numbers
/// Authority (IANA) in the "mail parameters" registry [9].  SMTP servers SHOULD NOT
/// use unregistered names.
///
/// Attdl-Protocol = Atom
pub fn attdl_protocol(input: &[u8]) -> IResult<&[u8], &str> {
    atom(input)
}
