use std::{
    io::Read,
    num::NonZero,
    path::{Path, PathBuf},
};

use aes::cipher::{BlockDecryptMut, KeyIvInit};
use crypto_bigint::{modular::runtime_mod::DynResidueParams, Encoding};
use vsss_rs::ReadableShareSet;

mod dynresidue;
mod ui;

type Identifier<const LIMBS: usize> = crate::dynresidue::IdentifierDynResidue<LIMBS>;
type U64Modulus =
    crypto_bigint::modular::runtime_mod::DynResidueParams<{ crypto_bigint::U64::LIMBS }>;
type U64Share = vsss_rs::DefaultShare<
    Identifier<{ crypto_bigint::U64::LIMBS }>,
    Identifier<{ crypto_bigint::U64::LIMBS }>,
>;
type Decryptor = cbc::Decryptor<aes::Aes256>;
type EncryptionKey = [u8; 32];
type EncryptionIv = [u8; 16];
type Dkek = [u8; 32];

// these values are just taken from the sc-hsm-tool source code
const MAX_PRIME_ITER: usize = 1000;
const KDF_ITERATIONS: usize = 10_000_000;
const MAGIC: &str = "Salted__";

fn build_args() -> clap::Command {
    clap::Command::new("sc-hsm-recrypt")
        .arg(
            clap::Arg::new("file")
                .required(true)
                .help("path to the dkek share file")
                .long("file")
                .short('f')
                .value_parser(clap::builder::PathBufValueParser::new()),
        )
        .arg(
            clap::Arg::new("shares-total")
                .required(true)
                .help("total number of shares")
                .long("shares-total")
                .value_parser(clap::builder::RangedU64ValueParser::<usize>::new().range(2..)),
        )
        .arg(
            clap::Arg::new("shares-required")
                .required(true)
                .help("minimum required number of shares")
                .long("shares-required")
                .value_parser(clap::builder::RangedU64ValueParser::<usize>::new().range(2..)),
        )
}

struct Args {
    dkek_file: PathBuf,
    shares_total: usize,
    shares_required: usize,
}

fn main() -> anyhow::Result<()> {
    let matches = build_args().get_matches();
    let dkek_file = matches
        .get_one::<PathBuf>("file")
        .expect("required arg")
        .clone();
    if !dkek_file.exists() {
        anyhow::bail!("specified dkek file does not exist!");
    }
    if !dkek_file.is_file() {
        anyhow::bail!("specified dkek file is not a file!");
    }
    let shares_total = *matches
        .get_one::<usize>("shares-total")
        .expect("required arg");
    let shares_required = *matches
        .get_one::<usize>("shares-required")
        .expect("required arg");
    if shares_required > shares_total {
        anyhow::bail!(
            "required number of shares must be less than or equal to total number of shares!"
        );
    }
    let args = Args {
        dkek_file,
        shares_total,
        shares_required,
    };

    crate::ui::init_term();
    let result = main_result(args);
    crate::ui::restore_term();
    result
}

fn main_result(args: Args) -> anyhow::Result<()> {
    let (_, shares) = crate::ui::get_shares(args.shares_required)?;
    println!("decrypting share...\r");
    let result = ReadableShareSet::combine(&shares).unwrap();
    let secret = result.retrieve();

    // decrypt the dkek backup to make sure we got the correct secret
    let _dkek = match decrypt_dkek(&args.dkek_file, &secret.to_be_bytes()) {
        Ok(dkek) => dkek,
        Err(e) => {
            anyhow::bail!("failed to decrypt: {e:?}\npossibly the entered share values are wrong?");
        }
    };

    let mut rng = rand::rngs::OsRng;
    // TODO: generate a new secret and reencrypt the dkek?
    let new_prime = generate_prime_min_with_rng(&mut rng, &secret).unwrap();
    let new_modulus = DynResidueParams::new(&new_prime);
    let shares = vsss_rs::shamir::split_secret_with_participant_generator::<U64Share>(
        args.shares_required,
        args.shares_total,
        &Identifier::new(&secret, new_modulus),
        &mut rng,
        &[vsss_rs::ParticipantIdGeneratorType::sequential(
            Some(Identifier::new(&crypto_bigint::U64::ONE, new_modulus)),
            Some(Identifier::new(&crypto_bigint::U64::ONE, new_modulus)),
            NonZero::new(3).unwrap(),
        )],
    )
    .unwrap();

    crate::ui::print_shares(new_modulus.modulus(), &shares)?;

    Ok(())
}

fn decrypt_dkek<P: AsRef<Path>>(file: P, share_secret: &[u8; 8]) -> anyhow::Result<Dkek> {
    let mut file = std::fs::File::open(file)?;
    let mut bytes = [0; 64]; // dkek files are always 64 bytes long
    file.read_exact(&mut bytes)?;
    if &bytes[0..8] != MAGIC.as_bytes() {
        anyhow::bail!("dkek file doesn't start with the correct header!");
    }
    let salt = &bytes[8..16];
    let mut data = [0; 48];
    data.copy_from_slice(&bytes[16..]);

    let (key, iv) = derive_key_iv(salt, share_secret);
    let dec = Decryptor::new(&key.into(), &iv.into())
        .decrypt_padded_mut::<cbc::cipher::block_padding::Pkcs7>(&mut data)?;
    let mut data = Dkek::default();
    data.copy_from_slice(dec);

    Ok(data)
}

// this is an impl of openssl's EVP_BytesToKey (according to the docs at least)
// but specifically for aes_256_cbc/md5/10_000_000 iterations
fn derive_key_iv(salt: &[u8], secret: &[u8; 8]) -> (EncryptionKey, EncryptionIv) {
    debug_assert!(salt.len() == 8);
    fn hash(previous: &[u8], salt: &[u8], secret: &[u8; 8]) -> [u8; 16] {
        debug_assert!(previous.len() <= 16);
        let mut full_data = [0_u8; 32];
        (&mut full_data[0..previous.len()]).copy_from_slice(previous);
        (&mut full_data[previous.len()..previous.len() + 8]).copy_from_slice(secret);
        (&mut full_data[previous.len() + 8..previous.len() + 16]).copy_from_slice(salt);

        let mut hash = *md5::compute(&full_data[..previous.len() + 16]);
        for _ in 1..KDF_ITERATIONS {
            hash = *md5::compute(hash);
        }
        hash
    }

    let d1 = hash(&[], salt, secret);
    let d2 = hash(&d1, salt, secret);
    let d3 = hash(&d2, salt, secret);

    let mut key = [0_u8; 32];
    (&mut key[0..16]).copy_from_slice(&d1);
    (&mut key[16..32]).copy_from_slice(&d2);
    (key, d3)
}

// generate a prime bigger than the given secret we want to encode
fn generate_prime_min_with_rng<const LIMBS: usize>(
    rng: &mut (impl rand::RngCore + rand::CryptoRng),
    min: &crypto_bigint::Uint<LIMBS>,
) -> Option<crypto_bigint::Uint<LIMBS>> {
    for _ in 0..MAX_PRIME_ITER {
        let prime =
            crypto_primes::generate_prime_with_rng(rng, Some(crypto_bigint::Uint::<LIMBS>::BITS));
        if prime > *min {
            return Some(prime);
        }
    }
    None
}
