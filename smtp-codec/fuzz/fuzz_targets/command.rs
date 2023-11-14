#![no_main]
use libfuzzer_sys::fuzz_target;
use smtp_codec::parse::command::command;

fuzz_target!(|data: &[u8]| {
    if let Ok((_, cmd)) = command(data) {
        // Fuzzer created a valid SMTP command.
        // dbg!(&cmd);

        let cmd2 = {
            // Let's serialize the command into bytes ...
            let mut buf = Vec::new();
            cmd.serialize(&mut buf).unwrap();

            // ... parse it again ...
            let (rem, cmd2) = command(&buf).unwrap();
            assert!(rem.is_empty());

            // dbg!(&cmd2);
            cmd2
        };

        // ... and verify that we got the same results.
        assert_eq!(cmd, cmd2);
    }
});
