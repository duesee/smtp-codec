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
    command::{Mailbox, Path, Reverse_path},
    imf::{
        datetime::date_time,
        folding_ws_and_comment::{CFWS, FWS},
        identification::msg_id,
    },
    Atom, Domain, String,
};

/// Return-path-line = "Return-Path:" FWS Reverse-path <CRLF>
pub fn Return_path_line(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = tuple((tag_no_case(b"Return-Path:"), FWS, Reverse_path, CRLF));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// Time-stamp-line = "Received:" FWS Stamp <CRLF>
pub fn Time_stamp_line(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = tuple((tag_no_case(b"Received:"), FWS, Stamp, CRLF));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// Stamp = From-domain By-domain Opt-info [CFWS] ";" FWS date-time
///
/// Caution: Where "date-time" is as defined in RFC 5322 [4]
///          but the "obs-" forms, especially two-digit
///          years, are prohibited in SMTP and MUST NOT be used.
pub fn Stamp(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = tuple((
        From_domain,
        By_domain,
        Opt_info,
        opt(CFWS),
        tag(b";"),
        FWS,
        date_time,
    ));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// From-domain = "FROM" FWS Extended-Domain
pub fn From_domain(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = tuple((tag_no_case(b"FROM"), FWS, Extended_Domain));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// By-domain = CFWS "BY" FWS Extended-Domain
pub fn By_domain(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = tuple((CFWS, tag_no_case(b"BY"), FWS, Extended_Domain));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// Extended-Domain = Domain /
///                   ( Domain FWS "(" TCP-info ")" ) /
///                   ( address-literal FWS "(" TCP-info ")" )
pub fn Extended_Domain(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = alt((
        recognize(Domain),
        recognize(tuple((Domain, FWS, tag(b"("), TCP_info, tag(b")")))),
        recognize(tuple((
            address_literal,
            FWS,
            tag(b"("),
            TCP_info,
            tag(b")"),
        ))),
    ));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// Information derived by server from TCP connection not client EHLO.
///
/// TCP-info = address-literal / ( Domain FWS address-literal )
pub fn TCP_info(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = alt((
        recognize(address_literal),
        recognize(tuple((Domain, FWS, address_literal))),
    ));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// Opt-info = [Via] [With] [ID] [For] [Additional-Registered-Clauses]
pub fn Opt_info(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = tuple((
        opt(Via),
        opt(With),
        opt(ID),
        opt(For),
        opt(Additional_Registered_Clauses),
    ));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// Via = CFWS "VIA" FWS Link
pub fn Via(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = tuple((CFWS, tag_no_case(b"VIA"), FWS, Link));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// With = CFWS "WITH" FWS Protocol
pub fn With(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = tuple((CFWS, tag_no_case(b"WITH"), FWS, Protocol));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// ID = CFWS "ID" FWS ( Atom / msg-id )
///       ; msg-id is defined in RFC 5322 [4]
pub fn ID(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = tuple((
        CFWS,
        tag_no_case(b"ID"),
        FWS,
        recognize(alt((recognize(Atom), msg_id))),
    ));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// For = CFWS "FOR" FWS ( Path / Mailbox )
pub fn For(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = tuple((
        CFWS,
        tag_no_case(b"FOR"),
        FWS,
        alt((recognize(Path), Mailbox)),
    ));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// Additional standard clauses may be added in this location by future standards and registration with
/// IANA.  SMTP servers SHOULD NOT use unregistered names.  See Section 8.
///
/// Additional-Registered-Clauses = CFWS Atom FWS String
pub fn Additional_Registered_Clauses(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = many1(tuple((CFWS, Atom, FWS, String)));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// Link = "TCP" / Addtl-Link
pub fn Link(input: &[u8]) -> IResult<&[u8], &str> {
    alt((map_res(tag_no_case("TCP"), std::str::from_utf8), Addtl_Link))(input)
}

/// Additional standard names for links are registered with the Internet Assigned Numbers
/// Authority (IANA).  "Via" is primarily of value with non-Internet transports.  SMTP servers
/// SHOULD NOT use unregistered names.
///
/// Addtl-Link = Atom
pub fn Addtl_Link(input: &[u8]) -> IResult<&[u8], &str> {
    Atom(input)
}

/// Protocol = "ESMTP" / "SMTP" / Attdl-Protocol
pub fn Protocol(input: &[u8]) -> IResult<&[u8], &str> {
    alt((
        map_res(tag_no_case(b"ESMTP"), std::str::from_utf8),
        map_res(tag_no_case(b"SMTP"), std::str::from_utf8),
        Attdl_Protocol,
    ))(input)
}

/// Additional standard names for protocols are registered with the Internet Assigned Numbers
/// Authority (IANA) in the "mail parameters" registry [9].  SMTP servers SHOULD NOT
/// use unregistered names.
///
/// Attdl-Protocol = Atom
pub fn Attdl_Protocol(input: &[u8]) -> IResult<&[u8], &str> {
    Atom(input)
}
