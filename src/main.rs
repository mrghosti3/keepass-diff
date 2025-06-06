extern crate base64;
extern crate clap;
extern crate keepass;
extern crate rpassword;
extern crate termcolor;

pub mod diff;
pub mod stack;

use clap::Parser;
use diff::{group::Group, Diff, DiffDisplay};
use keepass::{error::DatabaseOpenError, Database, DatabaseKey};

use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};

use std::borrow::Cow;
use std::fs::File;

type Str = Box<str>;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Sets the first file
    #[clap(name = "INPUT-A", index = 1)]
    input_a: Str,

    /// Sets the second file
    #[clap(name = "INPUT-B", index = 2)]
    input_b: Str,

    /// Disables color output
    #[clap(short = 'C', long = "no-color")]
    no_color: bool,

    /// Enables verbose output
    #[clap(short = 'v', long)]
    verbose: bool,

    /// Enables verbose output
    #[clap(short = 'm', long = "mask-passwords")]
    mask_passwords: bool,

    /// Sets the password for the first file (will be asked for if omitted)
    #[clap(name = "password-a", long)]
    password_a: Option<Str>,

    /// Sets the password for the second file (will be asked for if omitted)
    #[clap(name = "password-b", long)]
    password_b: Option<Str>,

    /// Sets the password for both files (if it's the same for both files)
    #[clap(name = "passwords", long, short)]
    passwords: Option<Str>,

    /// Asks for password only once, and tries to open both files with it
    #[clap(name = "same-password", long, short)]
    same_password: bool,

    /// Sets no password for the first file (and will not ask for it)
    #[clap(name = "no-password-a", long)]
    no_password_a: bool,

    /// Sets no password for the second file (and will not ask for it)
    #[clap(name = "no-password-b", long)]
    no_password_b: bool,

    /// Sets no password for both files (and will not ask for both files)
    #[clap(name = "no-passwords", long)]
    no_passwords: bool,

    /// Sets the key file for the first file
    #[clap(name = "keyfile-a", long)]
    keyfile_a: Option<Str>,

    /// Sets the key file for the second file
    #[clap(name = "keyfile-b", long)]
    keyfile_b: Option<Str>,

    /// Sets the same key file for both files (keyfile-a and keyfile-b would take precedence if set as well)
    #[clap(name = "keyfiles", long)]
    keyfiles: Option<Str>,
}

fn main() -> Result<(), ()> {
    let arguments = Args::parse();
    let use_color = !arguments.no_color;
    let use_verbose = arguments.verbose;
    let mask_passwords = arguments.mask_passwords;

    let (db_a, db_b) = {
        let file_a = &arguments.input_a;
        let file_b = &arguments.input_b;

        let pass_a: Option<Cow<str>> = match (
            arguments.password_a.as_deref(),
            arguments.passwords.as_deref(),
            arguments.same_password,
            arguments.no_password_a,
            arguments.no_passwords,
        ) {
            (Some(password), _, _, _, _) => Some(password.into()),
            (_, Some(password), _, _, _) => Some(password.into()),
            (_, _, true, _, _) => prompt_password(None).map(Into::into),
            (_, _, _, true, _) => None,
            (_, _, _, _, true) => None,
            _ => prompt_password(Some(file_a)).map(Into::into),
        };
        let pass_b: Option<Cow<str>> = match (
            arguments.password_b.as_deref(),
            arguments.passwords.as_deref(),
            arguments.same_password,
            arguments.no_password_b,
            arguments.no_passwords,
        ) {
            (Some(password), _, _, _, _) => Some(password.into()),
            (_, Some(password), _, _, _) => Some(password.into()),
            (_, _, true, _, _) => pass_a.clone(),
            (_, _, _, true, _) => None,
            (_, _, _, _, true) => None,
            _ => prompt_password(Some(file_b)).map(Into::into),
        };

        let keyfile_a = arguments.keyfile_a.as_deref();
        let keyfile_b = arguments.keyfile_b.as_deref();
        let keyfiles = arguments.keyfiles.as_deref();

        let keyfile_a = match (keyfile_a, keyfiles) {
            (None, None) => None,
            (Some(kfa), _) => Some(kfa),
            (_, Some(kfs)) => Some(kfs),
        };
        let keyfile_b = match (keyfile_b, keyfiles) {
            (None, None) => None,
            (Some(kfb), _) => Some(kfb),
            (_, Some(kfs)) => Some(kfs),
        };

        (
            kdbx_to_group(
                file_a,
                pass_a.as_deref(),
                keyfile_a,
                use_verbose,
                mask_passwords,
            )
            .expect("Error opening database A"),
            kdbx_to_group(
                file_b,
                pass_b.as_deref(),
                keyfile_b,
                use_verbose,
                mask_passwords,
            )
            .expect("Error opening database B"),
        )
    };

    let delta = db_a.diff(&db_b);
    println!(
        "{}",
        DiffDisplay {
            inner: delta,
            path: stack::Stack::empty(),
            use_color,
            use_verbose,
            mask_passwords,
        }
    );

    Ok(())
}

fn prompt_password(file_name: Option<&str>) -> Option<String> {
    let prompt = match file_name {
        Some(fname) => format!("Password for file {}: ", fname),
        None => "Password for both files: ".to_string(),
    };
    rpassword::prompt_password(prompt)
        .map(|s| if s.is_empty() { None } else { Some(s) })
        .unwrap_or(None)
}

pub fn kdbx_to_group(
    file: &str,
    password: Option<&str>,
    keyfile_path: Option<&str>,
    use_verbose: bool,
    mask_passwords: bool,
) -> Result<Group, DatabaseOpenError> {
    let db_key = get_database_key(password, keyfile_path)?;
    let db = Database::open(&mut File::open(file)?, db_key)?;
    Ok(Group::from_keepass(&db.root, use_verbose, mask_passwords))
}

fn get_database_key(
    password: Option<&str>,
    keyfile_path: Option<&str>,
) -> Result<DatabaseKey, std::io::Error> {
    let db_key = DatabaseKey::new();
    let db_key = match password {
        Some(pwd) => db_key.with_password(pwd),
        _ => db_key,
    };
    if let Some(path) = keyfile_path {
        db_key.with_keyfile(&mut File::open(path)?)
    } else {
        Ok(db_key)
    }
}

pub fn set_fg(color: Option<Color>) {
    let mut stdout = StandardStream::stdout(ColorChoice::Always);
    stdout.set_color(ColorSpec::new().set_fg(color)).expect("Setting colors in your console failed. Please use the --no-color flag to disable colors if the error persists.");
}

pub fn reset_color() {
    let mut stdout = StandardStream::stdout(ColorChoice::Always);
    stdout.reset().expect("Resetting colors in your console failed. Please use the --no-color flag to disable colors if the error persists.");
}
