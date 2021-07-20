//! Internet Message Format (RFC 5322)
//!
//! TODO: replace this with an IMF library, e.g. rustyknife?

/// 3.2.1.  Quoted characters
pub mod quoted_characters {
    use abnf_core::streaming::{is_VCHAR, WSP};
    use nom::{
        branch::alt,
        bytes::streaming::{tag, take_while_m_n},
        combinator::recognize,
        sequence::tuple,
        IResult,
    };

    use super::obsolete::obs_qp;

    /// quoted-pair = ("\" (VCHAR / WSP)) / obs-qp
    pub fn quoted_pair(input: &[u8]) -> IResult<&[u8], &[u8]> {
        let parser = alt((
            recognize(tuple((
                tag(b"\\"),
                alt((take_while_m_n(1, 1, is_VCHAR), WSP)),
            ))),
            obs_qp,
        ));

        let (remaining, parsed) = recognize(parser)(input)?;

        Ok((remaining, parsed))
    }
}

/// 3.2.2.  Folding White Space and Comments
pub mod folding_ws_and_comment {
    use nom::IResult;

    /// Folding white space
    ///
    /// FWS = ([*WSP CRLF] 1*WSP) / obs-FWS
    pub fn FWS(_input: &[u8]) -> IResult<&[u8], &[u8]> {
        unimplemented!()
    }

    // Printable US-ASCII characters not including "(", ")", or "\"
    //
    // ctext = %d33-39 / %d42-91 / %d93-126 / obs-ctext

    // ccontent = ctext / quoted-pair / comment

    // comment = "(" *([FWS] ccontent) [FWS] ")"

    /// CFWS = (1*([FWS] comment) [FWS]) / FWS
    pub fn CFWS(_input: &[u8]) -> IResult<&[u8], &[u8]> {
        unimplemented!()
    }
}

/// 3.2.3.  Atom
pub mod atom {
    use abnf_core::streaming::{is_ALPHA, is_DIGIT};
    use nom::{
        bytes::streaming::{tag, take_while1},
        combinator::{opt, recognize},
        multi::many0,
        sequence::tuple,
        IResult,
    };

    use super::folding_ws_and_comment::CFWS;

    /// Printable US-ASCII characters not including specials.
    /// Used for atoms.
    ///
    /// atext = ALPHA / DIGIT /
    ///          "!" / "#" /
    ///          "$" / "%" /
    ///          "&" / "'" /
    ///          "*" / "+" /
    ///          "-" / "/" /
    ///          "=" / "?" /
    ///          "^" / "_" /
    ///          "`" / "{" /
    ///          "|" / "}" /
    ///          "~"
    pub fn is_atext(byte: u8) -> bool {
        let allowed = b"!#$%&'*+-/=?^_`{|}~";

        is_ALPHA(byte) || is_DIGIT(byte) || allowed.contains(&byte)
    }

    /// atom = [CFWS] 1*atext [CFWS]
    pub fn atom(input: &[u8]) -> IResult<&[u8], &[u8]> {
        let parser = tuple((opt(CFWS), take_while1(is_atext), opt(CFWS)));

        let (remaining, parsed) = recognize(parser)(input)?;

        Ok((remaining, parsed))
    }

    /// dot-atom-text = 1*atext *("." 1*atext)
    pub fn dot_atom_text(input: &[u8]) -> IResult<&[u8], &[u8]> {
        let parser = tuple((
            take_while1(is_atext),
            many0(tuple((tag(b"."), take_while1(is_atext)))),
        ));

        let (remaining, parsed) = recognize(parser)(input)?;

        Ok((remaining, parsed))
    }

    // dot-atom = [CFWS] dot-atom-text [CFWS]
    pub fn dot_atom(input: &[u8]) -> IResult<&[u8], &[u8]> {
        let parser = tuple((opt(CFWS), dot_atom_text, opt(CFWS)));

        let (remaining, parsed) = recognize(parser)(input)?;

        Ok((remaining, parsed))
    }

    // Special characters that do not appear in atext.
    //
    // specials = "(" / ")" /
    //            "<" / ">" /
    //            "[" / "]" /
    //            ":" / ";" /
    //            "@" / "\" /
    //            "," / "." /
    //            DQUOTE
    // ...
}

/// 3.2.4.  Quoted Strings
pub mod quoted_strings {
    use abnf_core::streaming::DQUOTE;
    use nom::{
        branch::alt,
        bytes::streaming::take_while_m_n,
        combinator::{opt, recognize},
        multi::many0,
        sequence::tuple,
        IResult,
    };

    use super::{
        folding_ws_and_comment::{CFWS, FWS},
        obsolete::is_obs_qtext,
        quoted_characters::quoted_pair,
    };

    /// Printable US-ASCII characters not including "\" or the quote character.
    ///
    /// qtext = %d33 / %d35-91 / %d93-126 / obs-qtext
    pub fn is_qtext(byte: u8) -> bool {
        match byte {
            33 | 35..=91 | 93..=126 => true,
            _ if is_obs_qtext(byte) => true,
            _ => false,
        }
    }

    /// qcontent = qtext / quoted-pair
    pub fn qcontent(input: &[u8]) -> IResult<&[u8], &[u8]> {
        let parser = alt((take_while_m_n(1, 1, is_qtext), quoted_pair));

        let (remaining, parsed) = recognize(parser)(input)?;

        Ok((remaining, parsed))
    }

    /// quoted-string = [CFWS] DQUOTE *([FWS] qcontent) [FWS] DQUOTE [CFWS]
    pub fn quoted_string(input: &[u8]) -> IResult<&[u8], &[u8]> {
        let parser = tuple((
            opt(CFWS),
            DQUOTE,
            many0(tuple((opt(FWS), qcontent))),
            opt(FWS),
            DQUOTE,
            opt(CFWS),
        ));

        let (remaining, parsed) = recognize(parser)(input)?;

        Ok((remaining, parsed))
    }
}

/// 3.2.5.  Miscellaneous Tokens
pub mod miscellaneous {
    use nom::{branch::alt, IResult};

    use super::{atom::atom, quoted_strings::quoted_string};

    /// word = atom / quoted-string
    pub fn word(input: &[u8]) -> IResult<&[u8], &[u8]> {
        alt((atom, quoted_string))(input)
    }

    // phrase = 1*word / obs-phrase
    // ...

    // unstructured = (*([FWS] VCHAR) *WSP) / obs-unstruct
    // ...
}

/// 3.3.  Date and Time Specification
pub mod datetime {
    use abnf_core::streaming::is_DIGIT;
    use nom::{
        branch::alt,
        bytes::streaming::{tag, tag_no_case, take_while_m_n},
        combinator::{opt, recognize},
        sequence::tuple,
        IResult,
    };

    use super::folding_ws_and_comment::{CFWS, FWS};

    // date-time = [ day-of-week "," ] date time [CFWS]
    pub fn date_time(input: &[u8]) -> IResult<&[u8], &[u8]> {
        let parser = tuple((opt(tuple((day_of_week, tag(b",")))), date, time, opt(CFWS)));

        let (remaining, parsed) = recognize(parser)(input)?;

        Ok((remaining, parsed))
    }

    // day-of-week = ([FWS] day-name) / obs-day-of-week
    pub fn day_of_week(input: &[u8]) -> IResult<&[u8], &[u8]> {
        let parser = tuple((opt(FWS), day_name));

        let (remaining, parsed) = recognize(parser)(input)?;

        Ok((remaining, parsed))
    }

    // day-name = "Mon" / "Tue" / "Wed" / "Thu" / "Fri" / "Sat" / "Sun"
    pub fn day_name(input: &[u8]) -> IResult<&[u8], &[u8]> {
        let parser = alt((
            tag_no_case(b"Mon"),
            tag_no_case(b"Tue"),
            tag_no_case(b"Wed"),
            tag_no_case(b"Thu"),
            tag_no_case(b"Fri"),
            tag_no_case(b"Sat"),
            tag_no_case(b"Sun"),
        ));

        let (remaining, parsed) = recognize(parser)(input)?;

        Ok((remaining, parsed))
    }

    // date = day month year
    pub fn date(input: &[u8]) -> IResult<&[u8], &[u8]> {
        let parser = tuple((day, month, year));

        let (remaining, parsed) = recognize(parser)(input)?;

        Ok((remaining, parsed))
    }

    // day = ([FWS] 1*2DIGIT FWS) / obs-day
    pub fn day(input: &[u8]) -> IResult<&[u8], &[u8]> {
        let parser = tuple((opt(FWS), take_while_m_n(1, 2, is_DIGIT), FWS));

        let (remaining, parsed) = recognize(parser)(input)?;

        Ok((remaining, parsed))
    }

    // month = "Jan" / "Feb" / "Mar" / "Apr" / "May" / "Jun" / "Jul" / "Aug" / "Sep" / "Oct" / "Nov" / "Dec"
    pub fn month(input: &[u8]) -> IResult<&[u8], &[u8]> {
        let parser = alt((
            tag_no_case(b"Jan"),
            tag_no_case(b"Feb"),
            tag_no_case(b"Mar"),
            tag_no_case(b"Apr"),
            tag_no_case(b"May"),
            tag_no_case(b"Jun"),
            tag_no_case(b"Jul"),
            tag_no_case(b"Aug"),
            tag_no_case(b"Sep"),
            tag_no_case(b"Oct"),
            tag_no_case(b"Nov"),
            tag_no_case(b"Dec"),
        ));

        let (remaining, parsed) = recognize(parser)(input)?;

        Ok((remaining, parsed))
    }

    // year = (FWS 4*DIGIT FWS) / obs-year
    pub fn year(input: &[u8]) -> IResult<&[u8], &[u8]> {
        let parser = tuple((FWS, take_while_m_n(4, 8, is_DIGIT), FWS)); // FIXME: 4*?!

        let (remaining, parsed) = recognize(parser)(input)?;

        Ok((remaining, parsed))
    }

    // time = time-of-day zone
    pub fn time(input: &[u8]) -> IResult<&[u8], &[u8]> {
        let parser = tuple((time_of_day, zone));

        let (remaining, parsed) = recognize(parser)(input)?;

        Ok((remaining, parsed))
    }

    // time-of-day = hour ":" minute [ ":" second ]
    pub fn time_of_day(input: &[u8]) -> IResult<&[u8], &[u8]> {
        let parser = tuple((hour, tag(b":"), minute, opt(tuple((tag(b":"), second)))));

        let (remaining, parsed) = recognize(parser)(input)?;

        Ok((remaining, parsed))
    }

    // hour = 2DIGIT / obs-hour
    pub fn hour(input: &[u8]) -> IResult<&[u8], &[u8]> {
        // FIXME: obs- forms must not be used in SMTP. Never?

        let parser = take_while_m_n(2, 2, is_DIGIT);

        let (remaining, parsed) = recognize(parser)(input)?;

        Ok((remaining, parsed))
    }

    // minute = 2DIGIT / obs-minute
    pub fn minute(input: &[u8]) -> IResult<&[u8], &[u8]> {
        // FIXME: obs- forms must not be used in SMTP. Never?

        let parser = take_while_m_n(2, 2, is_DIGIT);

        let (remaining, parsed) = recognize(parser)(input)?;

        Ok((remaining, parsed))
    }

    // second = 2DIGIT / obs-second
    pub fn second(input: &[u8]) -> IResult<&[u8], &[u8]> {
        // FIXME: obs- forms must not be used in SMTP. Never?

        let parser = take_while_m_n(2, 2, is_DIGIT);

        let (remaining, parsed) = recognize(parser)(input)?;

        Ok((remaining, parsed))
    }

    // zone = (FWS ( "+" / "-" ) 4DIGIT) / obs-zone
    pub fn zone(input: &[u8]) -> IResult<&[u8], &[u8]> {
        // FIXME: obs- forms must not be used in SMTP. Never?

        let parser = tuple((
            FWS,
            alt((tag(b"+"), tag(b"-"))),
            take_while_m_n(4, 4, is_DIGIT),
        ));

        let (remaining, parsed) = recognize(parser)(input)?;

        Ok((remaining, parsed))
    }
}

/// 3.4.1.  Addr-Spec Specification
pub mod addr_spec {
    use nom::{
        branch::alt,
        bytes::streaming::{tag, take_while_m_n},
        combinator::{opt, recognize},
        multi::many0,
        sequence::tuple,
        IResult,
    };

    use super::{
        atom::dot_atom,
        folding_ws_and_comment::{CFWS, FWS},
        obsolete::{obs_domain, obs_dtext, obs_local_part},
        quoted_strings::quoted_string,
    };

    // addr-spec = local-part "@" domain

    /// local-part = dot-atom / quoted-string / obs-local-part
    pub fn local_part(input: &[u8]) -> IResult<&[u8], &[u8]> {
        let parser = alt((dot_atom, quoted_string, obs_local_part));

        let (remaining, parsed) = recognize(parser)(input)?;

        Ok((remaining, parsed))
    }

    /// domain = dot-atom / domain-literal / obs-domain
    pub fn domain(input: &[u8]) -> IResult<&[u8], &[u8]> {
        let parser = alt((dot_atom, domain_literal, obs_domain));

        let (remaining, parsed) = recognize(parser)(input)?;

        Ok((remaining, parsed))
    }

    /// domain-literal = [CFWS] "[" *([FWS] dtext) [FWS] "]" [CFWS]
    pub fn domain_literal(input: &[u8]) -> IResult<&[u8], &[u8]> {
        let parser = tuple((
            opt(CFWS),
            tag(b"["),
            many0(tuple((opt(FWS), dtext))),
            opt(FWS),
            tag(b"]"),
            opt(CFWS),
        ));

        let (remaining, parsed) = recognize(parser)(input)?;

        Ok((remaining, parsed))
    }

    /// Printable US-ASCII characters not including "[", "]", or "\".
    ///
    /// dtext = %d33-90 / %d94-126 / obs-dtext
    pub fn dtext(input: &[u8]) -> IResult<&[u8], &[u8]> {
        fn is_a(byte: u8) -> bool {
            matches!(byte, 33..=90)
        }

        fn is_b(byte: u8) -> bool {
            matches!(byte, 94..=126)
        }

        let parser = alt((
            take_while_m_n(1, 1, is_a),
            take_while_m_n(1, 1, is_b),
            obs_dtext,
        ));

        let (remaining, parsed) = recognize(parser)(input)?;

        Ok((remaining, parsed))
    }
}

/// 3.6.4.  Identification Fields
pub mod identification {
    use nom::{
        branch::alt,
        bytes::streaming::tag,
        combinator::{opt, recognize},
        multi::many0,
        sequence::{delimited, tuple},
        IResult,
    };

    use super::{
        addr_spec::dtext,
        atom::dot_atom_text,
        folding_ws_and_comment::CFWS,
        obsolete::{obs_id_left, obs_id_right},
    };

    // message-id = "Message-ID:" msg-id CRLF
    // ...

    // in-reply-to = "In-Reply-To:" 1*msg-id CRLF
    // ...

    // references = "References:" 1*msg-id CRLF
    // ...

    /// msg-id = [CFWS] "<" id-left "@" id-right ">" [CFWS]
    pub fn msg_id(input: &[u8]) -> IResult<&[u8], &[u8]> {
        let parser = tuple((
            opt(CFWS),
            tag(b"<"),
            id_left,
            tag(b"@"),
            id_right,
            tag(b">"),
            opt(CFWS),
        ));

        let (remaining, parsed) = recognize(parser)(input)?;

        Ok((remaining, parsed))
    }

    /// id-left = dot-atom-text / obs-id-left
    pub fn id_left(input: &[u8]) -> IResult<&[u8], &[u8]> {
        let parser = alt((dot_atom_text, obs_id_left));

        let (remaining, parsed) = recognize(parser)(input)?;

        Ok((remaining, parsed))
    }

    /// id-right = dot-atom-text / no-fold-literal / obs-id-right
    pub fn id_right(input: &[u8]) -> IResult<&[u8], &[u8]> {
        let parser = alt((dot_atom_text, no_fold_literal, obs_id_right));

        let (remaining, parsed) = recognize(parser)(input)?;

        Ok((remaining, parsed))
    }

    // no-fold-literal = "[" *dtext "]"
    pub fn no_fold_literal(input: &[u8]) -> IResult<&[u8], &[u8]> {
        let parser = delimited(tag(b"["), many0(dtext), tag(b"]"));

        let (remaining, parsed) = recognize(parser)(input)?;

        Ok((remaining, parsed))
    }
}

/// 4.1.  Miscellaneous Obsolete Tokens
pub mod obsolete {
    use abnf_core::streaming::{CR, LF};
    use nom::{
        branch::alt,
        bytes::streaming::{tag, take_while_m_n},
        combinator::recognize,
        multi::many0,
        sequence::tuple,
        IResult,
    };

    use super::{
        addr_spec::{domain, local_part},
        atom::atom,
        miscellaneous::word,
        quoted_characters::quoted_pair,
    };

    /// US-ASCII control characters that do not include the carriage
    /// return, line feed, and white space characters
    ///
    /// obs-NO-WS-CTL = %d1-8 / %d11 / %d12 / %d14-31 / %d127
    pub fn is_obs_NO_WS_CTL(byte: u8) -> bool {
        matches!(byte, 1..=8 | 11 | 12 | 14..=31 | 127)
    }

    /// obs-qtext = obs-NO-WS-CTL
    pub fn is_obs_qtext(byte: u8) -> bool {
        is_obs_NO_WS_CTL(byte)
    }

    /// obs-qp = "\" (%d0 / obs-NO-WS-CTL / LF / CR)
    pub fn obs_qp(input: &[u8]) -> IResult<&[u8], &[u8]> {
        let parser = tuple((
            tag(b"\\"),
            alt((
                take_while_m_n(1, 1, |x| x == 0x00),
                take_while_m_n(1, 1, is_obs_NO_WS_CTL),
                LF,
                CR,
            )),
        ));

        let (remaining, parsed) = recognize(parser)(input)?;

        Ok((remaining, parsed))
    }

    // 4.4.  Obsolete Addressing (RFC 5322)

    /// obs-local-part = word *("." word)
    pub fn obs_local_part(input: &[u8]) -> IResult<&[u8], &[u8]> {
        let parser = tuple((word, many0(tuple((tag(b"."), word)))));

        let (remaining, parsed) = recognize(parser)(input)?;

        Ok((remaining, parsed))
    }

    /// obs-domain = atom *("." atom)
    pub fn obs_domain(input: &[u8]) -> IResult<&[u8], &[u8]> {
        let parser = tuple((atom, many0(tuple((tag(b"."), atom)))));

        let (remaining, parsed) = recognize(parser)(input)?;

        Ok((remaining, parsed))
    }

    /// obs-dtext = obs-NO-WS-CTL / quoted-pair
    pub fn obs_dtext(input: &[u8]) -> IResult<&[u8], &[u8]> {
        let parser = alt((take_while_m_n(1, 1, is_obs_NO_WS_CTL), quoted_pair));

        let (remaining, parsed) = recognize(parser)(input)?;

        Ok((remaining, parsed))
    }

    // 4.5.4.  Obsolete Identification Fields (RFC 5322)

    /// obs-id-left = local-part
    pub fn obs_id_left(input: &[u8]) -> IResult<&[u8], &[u8]> {
        local_part(input)
    }

    /// obs-id-right = domain
    pub fn obs_id_right(input: &[u8]) -> IResult<&[u8], &[u8]> {
        domain(input)
    }
}
