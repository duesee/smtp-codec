#![allow(non_snake_case)]

use abnf_core::streaming::{is_ALPHA, is_DIGIT};
use nom::{
    branch::alt,
    bytes::streaming::{tag, take_while},
    combinator::{map_res, opt, recognize},
    sequence::tuple,
    IResult,
};
use std::str::from_utf8;

pub mod address;
pub mod command;
pub mod imf;
pub mod replies;
pub mod response;
pub mod trace;
pub mod utils;

fn is_base64_char(i: u8) -> bool {
    is_ALPHA(i) || is_DIGIT(i) || i == b'+' || i == b'/'
}

pub fn base64(input: &[u8]) -> IResult<&[u8], &str> {
    let parser = map_res(
        recognize(tuple((
            take_while(is_base64_char),
            opt(alt((tag("=="), tag("=")))),
        ))),
        from_utf8,
    );

    let (remaining, base64) = parser(input)?;

    Ok((remaining, base64))
}
