use nom::FindSubstring;
use smtp_codec::{
    parse::{
        command::command,
        response::{ehlo_ok_rsp, Greeting, Reply_lines},
    },
    types::Command,
};

fn parse_trace(mut trace: &[u8]) {
    let (rem, greeting) = Greeting(trace).unwrap();
    println!("S: {:?}", greeting);
    trace = rem;

    loop {
        if trace.is_empty() {
            break;
        }

        let (rem, cmd) = command(trace).unwrap();
        println!("C: {:?}", cmd);
        trace = rem;

        match cmd {
            Command::Ehlo { .. } => {
                let (rem, rsp) = ehlo_ok_rsp(trace).unwrap();
                println!("S: {:?}", rsp);
                trace = rem;
            }
            Command::Data { .. } => {
                let (rem, rsp) = Reply_lines(trace).unwrap();
                println!("S: {:?}", rsp);
                trace = rem;

                let pos = trace.find_substring("\r\n.\r\n").unwrap();
                let (data, rem) = trace.split_at(pos + 5);
                println!("C (data): <{}>", std::str::from_utf8(data).unwrap());
                trace = rem;

                let (rem, rsp) = Reply_lines(trace).unwrap();
                println!("S: {:?}", rsp);
                trace = rem;
            }
            _ => {
                let (rem, rsp) = Reply_lines(trace).unwrap();
                println!("S: {:?}", rsp);
                trace = rem;
            }
        }
    }
}

#[test]
/// D.1.  A Typical SMTP Transaction Scenario
fn test_trace_d_1() {
    let trace = b"\
220 foo.com Simple Mail Transfer Service Ready\r
EHLO bar.com\r
250-foo.com greets bar.com\r
250-8BITMIME\r
250-SIZE\r
250-DSN\r
250 HELP\r
MAIL FROM:<Smith@bar.com>\r
250 OK\r
RCPT TO:<Jones@foo.com>\r
250 OK\r
RCPT TO:<Green@foo.com>\r
550 No such user here\r
RCPT TO:<Brown@foo.com>\r
250 OK\r
DATA\r
354 Start mail input; end with <CRLF>.<CRLF>\r
Blah blah blah...\r
...etc. etc. etc.\r
.\r
250 OK\r
QUIT\r
221 foo.com Service closing transmission channel\r
";

    parse_trace(trace);
}

#[test]
/// D.2.  Aborted SMTP Transaction Scenario
fn test_trace_d_2() {
    let trace = b"\
220 foo.com Simple Mail Transfer Service Ready\r
EHLO bar.com\r
250-foo.com greets bar.com\r
250-8BITMIME\r
250-SIZE\r
250-DSN\r
250 HELP\r
MAIL FROM:<Smith@bar.com>\r
250 OK\r
RCPT TO:<Jones@foo.com>\r
250 OK\r
RCPT TO:<Green@foo.com>\r
550 No such user here\r
RSET\r
250 OK\r
QUIT\r
221 foo.com Service closing transmission channel\r
";

    parse_trace(trace);
}

#[test]
/// D.3.  Relayed Mail Scenario
fn test_trace_d_3() {
    let step_1 = b"\
220 foo.com Simple Mail Transfer Service Ready\r
EHLO bar.com\r
250-foo.com greets bar.com\r
250-8BITMIME\r
250-SIZE\r
250-DSN\r
250 HELP\r
MAIL FROM:<JQP@bar.com>\r
250 OK\r
RCPT TO:<Jones@XYZ.COM>\r
250 OK\r
DATA\r
354 Start mail input; end with <CRLF>.<CRLF>\r
Date: Thu, 21 May 1998 05:33:29 -0700\r
From: John Q. Public <JQP@bar.com>\r
Subject: The Next Meeting of the Board\r
To: Jones@xyz.com\r
\r
Bill:\r
The next meeting of the board of directors will be\r
on Tuesday.\r
John.\r
.\r
250 OK\r
QUIT\r
221 foo.com Service closing transmission channel\r
";

    let step_2 = b"\
220 xyz.com Simple Mail Transfer Service Ready\r
EHLO foo.com\r
250 xyz.com is on the air\r
MAIL FROM:<JQP@bar.com>\r
250 OK\r
RCPT TO:<Jones@XYZ.COM>\r
250 OK\r
DATA\r
354 Start mail input; end with <CRLF>.<CRLF>\r
Received: from bar.com by foo.com ; Thu, 21 May 1998\r
    05:33:29 -0700\r
Date: Thu, 21 May 1998 05:33:22 -0700\r
From: John Q. Public <JQP@bar.com>\r
Subject:  The Next Meeting of the Board\r
To: Jones@xyz.com\r
\r
Bill:\r
The next meeting of the board of directors will be\r
on Tuesday.\r
                        John.\r
.\r
250 OK\r
QUIT\r
221 foo.com Service closing transmission channel\r
";

    parse_trace(step_1);
    parse_trace(step_2);
}

#[test]
/// D.4.  Verifying and Sending Scenario
fn test_trace_d_4() {
    let trace = b"\
220 foo.com Simple Mail Transfer Service Ready\r
EHLO bar.com\r
250-foo.com greets bar.com\r
250-8BITMIME\r
250-SIZE\r
250-DSN\r
250-VRFY\r
250 HELP\r
VRFY Crispin\r
250 Mark Crispin <Admin.MRC@foo.com>\r
MAIL FROM:<EAK@bar.com>\r
250 OK\r
RCPT TO:<Admin.MRC@foo.com>\r
250 OK\r
DATA\r
354 Start mail input; end with <CRLF>.<CRLF>\r
Blah blah blah...\r
...etc. etc. etc.\r
.\r
250 OK\r
QUIT\r
221 foo.com Service closing transmission channel\r
";

    parse_trace(trace);
}
