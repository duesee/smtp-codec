use nom::{
    character::streaming::{line_ending, not_line_ending},
    IResult,
};

pub fn single_line(input: &[u8]) -> IResult<&[u8], String> {
    let (rem, (line, _)) = nom::sequence::tuple((not_line_ending, line_ending))(input)?;

    Ok((rem, String::from_utf8(line.to_vec()).unwrap()))
}
