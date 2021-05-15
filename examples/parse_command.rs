use smtp_codec::parse::command::command;
use std::io::Write;

fn main() -> std::io::Result<()> {
    let mut args = std::env::args();

    if let Some(path) = args.nth(1) {
        let data = std::fs::read(path).unwrap();

        match command(&data) {
            Ok((remaining, command)) => {
                println!("[!] {:#?}", command);
                let serialized = {
                    let mut serialized = Vec::new();
                    command.serialize(&mut serialized).unwrap();
                    String::from_utf8(serialized).unwrap()
                };
                print!("[!] {}", serialized);

                if !remaining.is_empty() {
                    println!("Remaining data in buffer: {:?}", remaining);
                }
            }
            Err(error) => {
                println!("Error parsing the command. Is it correct? ({:?})", error);
            }
        }

        return Ok(());
    }

    loop {
        let line = {
            print!("Enter SMTP command (or \"exit\"): ");
            std::io::stdout().flush().unwrap();

            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            line.replace("\n", "\r\n")
        };

        if line.trim() == "exit" {
            break;
        }

        match command(line.as_bytes()) {
            Ok((remaining, command)) => {
                println!("[!] {:#?}", command);
                let serialized = {
                    let mut serialized = Vec::new();
                    command.serialize(&mut serialized).unwrap();
                    String::from_utf8(serialized).unwrap()
                };
                print!("[!] {}", serialized);

                if !remaining.is_empty() {
                    println!("Remaining data in buffer: {:?}", remaining);
                }
            }
            Err(error) => {
                println!("Error parsing the command. Is it correct? ({:?})", error);
            }
        }
    }

    Ok(())
}
