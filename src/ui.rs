use std::io::Write;

use crypto_bigint::ArrayEncoding;

use crate::{Identifier, U64Modulus, U64Share};

pub fn init_term() {
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore_term();
        hook(info);
    }));

    crossterm::terminal::enable_raw_mode().expect("failed to init terminal");
    crossterm::execute!(std::io::stdout(), crossterm::terminal::EnterAlternateScreen)
        .expect("failed to init terminal");
}

pub fn restore_term() {
    if let Err(e) =
        crossterm::execute!(std::io::stdout(), crossterm::terminal::LeaveAlternateScreen)
    {
        eprintln!("failed to restore terminal: {e}");
    }
    if let Err(e) = crossterm::terminal::disable_raw_mode() {
        eprintln!("failed to restore terminal: {e}");
    }
}

struct Input {
    text: String,
    char_index: usize,
}

impl Input {
    pub fn new() -> Self {
        Self {
            text: String::new(),
            char_index: 0,
        }
    }

    fn byte_index(&self) -> usize {
        self.text
            .char_indices()
            .nth(self.char_index)
            .map_or_else(|| self.text.len(), |(i, _)| i)
    }

    fn cursor_right(&mut self) {
        let pos = self.char_index.saturating_add(1);
        self.char_index = pos.clamp(0, self.text.chars().count());
    }

    fn cursor_left(&mut self) {
        let pos = self.char_index.saturating_sub(1);
        self.char_index = pos.clamp(0, self.text.chars().count());
    }

    fn event_loop(mut self) -> anyhow::Result<String> {
        loop {
            let crossterm::event::Event::Key(key) = crossterm::event::read()? else {
                continue;
            };
            if key.kind != crossterm::event::KeyEventKind::Press {
                continue;
            }

            let prev_cursor = self.char_index;

            match key.code {
                crossterm::event::KeyCode::Char('c')
                    if key.modifiers == crossterm::event::KeyModifiers::CONTROL =>
                {
                    anyhow::bail!("ctrl+c");
                }
                crossterm::event::KeyCode::Char(c) => {
                    self.text.insert(self.byte_index(), c);
                    self.cursor_right();
                }
                crossterm::event::KeyCode::Left => self.cursor_left(),
                crossterm::event::KeyCode::Right => self.cursor_right(),
                crossterm::event::KeyCode::Backspace if self.char_index > 0 => {
                    let left = self.text.chars().take(self.char_index - 1);
                    let right = self.text.chars().skip(self.char_index);
                    self.text = left.chain(right).collect();
                    self.cursor_left();
                }
                crossterm::event::KeyCode::End => self.char_index = self.text.chars().count(),
                crossterm::event::KeyCode::Home => self.char_index = 0,
                crossterm::event::KeyCode::Enter => return Ok(self.text),
                _ => (),
            }

            if prev_cursor > 0 {
                crossterm::execute!(
                    std::io::stdout(),
                    crossterm::cursor::MoveLeft(prev_cursor as _)
                )?;
            }
            crossterm::execute!(
                std::io::stdout(),
                crossterm::terminal::Clear(crossterm::terminal::ClearType::UntilNewLine)
            )?;
            print!("{}", self.text);
            let cursor_delta = self.text.chars().count() - self.char_index;
            if cursor_delta > 0 {
                crossterm::execute!(
                    std::io::stdout(),
                    crossterm::cursor::MoveLeft(cursor_delta as _)
                )?;
            }
            std::io::stdout().flush()?;
        }
    }

    pub fn do_input() -> anyhow::Result<String> {
        Self::new().event_loop()
    }
}

fn clear_window() -> anyhow::Result<()> {
    crossterm::execute!(std::io::stdout(), crossterm::cursor::MoveTo(0, 0))?;
    crossterm::execute!(
        std::io::stdout(),
        crossterm::terminal::Clear(crossterm::terminal::ClearType::All)
    )?;
    Ok(())
}

fn wait_for_enter() -> anyhow::Result<()> {
    loop {
        match crossterm::event::read()? {
            crossterm::event::Event::Key(crossterm::event::KeyEvent {
                code: crossterm::event::KeyCode::Enter,
                kind: crossterm::event::KeyEventKind::Press,
                ..
            }) => return Ok(()),
            _ => (),
        }
    }
}

pub fn get_shares(num_shares: usize) -> anyhow::Result<(U64Modulus, Vec<U64Share>)> {
    let mut shares = Vec::with_capacity(num_shares);

    let mut err = None;
    let modulus = loop {
        clear_window()?;
        if let Some(err) = err {
            println!("entered prime is invalid! {err:?}\r\nplease try again\r\n");
        }
        print!("enter public prime: ");
        std::io::stdout().flush()?;
        let input = Input::do_input()?;
        let modulus = parse_hex_string(&input);
        match modulus {
            Ok(modulus) => break U64Modulus::new(&modulus),
            Err(e) => err = Some(e),
        }
    };

    for _ in 0..num_shares {
        clear_window()?;
        println!("press enter when ready to input the next share\r");
        wait_for_enter()?;
        let mut err = None;
        let share = loop {
            clear_window()?;
            if let Some(err) = err {
                println!("entered share is invalid! {err:?}\r\nplease try again\r\n");
            }
            print!("share id   : ");
            std::io::stdout().flush()?;
            let share_id = Input::do_input()?;
            print!("\r\nshare value: ");
            std::io::stdout().flush()?;
            let share_value = Input::do_input()?;

            let id = share_id
                .parse::<u64>()
                .map_err(|_| InputValidationError::InvalidInteger);
            let value = parse_hex_string(&share_value);

            match (id, value) {
                (Ok(id), Ok(value)) => {
                    break U64Share {
                        identifier: Identifier::new(&crypto_bigint::U64::from_u64(id), modulus),
                        value: Identifier::new(&value, modulus),
                    }
                }
                (Err(e), _) | (_, Err(e)) => err = Some(e),
            }
        };
        shares.push(share);
    }
    clear_window()?;

    Ok((modulus, shares))
}

pub fn print_shares(modulus: &crypto_bigint::U64, shares: &[U64Share]) -> anyhow::Result<()> {
    for share in shares {
        clear_window()?;
        println!("press enter when ready to print the next share\r");
        wait_for_enter()?;
        clear_window()?;
        let id = share.identifier.retrieve().as_words()[0];
        println!("prime       : {}\r", format_bigint(modulus));
        println!("share id    : {}\r", id);
        println!("share value : {}\r", format_bigint(&share.value.retrieve()));
        println!("\npress enter to continue\r");
        wait_for_enter()?;
    }
    Ok(())
}

#[derive(Debug)]
enum InputValidationError {
    InvalidInteger,
    InputNotHex,
    WrongLength,
    Other,
}

fn parse_hex_string<S: AsRef<str>>(input: S) -> Result<crypto_bigint::U64, InputValidationError> {
    let input = input.as_ref();
    if input.chars().any(|c| !c.is_ascii_hexdigit() && c != ':') {
        return Err(InputValidationError::InputNotHex);
    }
    let input = input.replace(':', "");
    if input.len() != 16 {
        return Err(InputValidationError::WrongLength);
    }

    // apparently the crypto_bigint numbers don't have some kind of hex parsing mechanism that doesn't panic???
    // whew this feels so wrong to do...
    // catch_unwind will not prevent the hook from being called, which would restore the terminal
    // so uhh. yeah. take it and restore afterwards.
    let hook = std::panic::take_hook();
    let result = std::panic::catch_unwind(move || crypto_bigint::U64::from_be_hex(&input))
        .map_err(|_| InputValidationError::Other);
    std::panic::set_hook(hook);
    return result;
}

fn format_bigint(val: &crypto_bigint::U64) -> String {
    let bytes: &[u8] = &*val.to_be_byte_array();
    bytes
        .into_iter()
        .map(|b| format!("{:02x}:", b))
        .collect::<String>()
        .trim_end_matches(':')
        .to_owned()
}
