extern crate bn;
extern crate rand;
extern crate serde;
extern crate serde_json;

use std::string::String;
use std::ops::Neg;
use bn::*;
use crypto::digest::Digest;
use crypto::sha3::Sha3;
use bincode::SizeLimit::Infinite;
use bincode::rustc_serialize::encode;
use rustc_serialize::hex::ToHex;
use rand::Rng;
use policy::msp::AbePolicy;
use tools::*;
use secretsharing::*;

/// An AC17 Public Key (PK)
#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Ac17PublicKey {
    pub _g: bn::G1,
    pub _h_a: Vec<bn::G2>,
    pub _e_gh_ka: Vec<bn::Gt>,
}

/// An AC17 Public Key (MK)
#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Ac17MasterKey {
    pub _g: bn::G1,
    pub _h: bn::G2,
    pub _g_k: Vec<bn::G1>,
    pub _a: Vec<bn::Fr>,
    pub _b: Vec<bn::Fr>,
}

/// An AC17 Ciphertext (CT)
#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Ac17Ciphertext {
    pub _c_0: Vec<bn::G2>,
    pub _c: Vec<(String, Vec<bn::G1>)>,
    pub _c_p: bn::Gt,
    pub _ct: Vec<u8>,
    pub _iv: [u8; 16],
}

/// An AC17 CP-ABE Ciphertext (CT), composed of a policy and an Ac17Ciphertext.
#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Ac17CpCiphertext {
    pub _policy: String,
    pub _ct: Ac17Ciphertext,
}

/// An AC17 KP-ABE Ciphertext (CT), composed of a set of attributes and an Ac17Ciphertext.
#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Ac17KpCiphertext {
    pub _attr: Vec<(String)>,
    pub _ct: Ac17Ciphertext,
}

/// An AC17 Secret Key (SK)
#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Ac17SecretKey {
    pub _k_0: Vec<bn::G2>,
    pub _k: Vec<(String, Vec<(bn::G1)>)>,
    pub _k_p: Vec<bn::G1>,
}

/// An AC17 KP-ABE Secret Key (SK), composed of a policy and an Ac17Ciphertext.
#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Ac17KpSecretKey {
    pub _policy: String,
    pub _sk: Ac17SecretKey,
}

/// An AC17 CP-ABE Secret Key (SK), composed of a set of attributes and an Ac17Ciphertext.
#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Ac17CpSecretKey {
    pub _attr: Vec<(String)>,
    pub _sk: Ac17SecretKey,
}

/// An AC17 Context for C
#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Ac17Context {
    pub _msk: Ac17MasterKey,
    pub _pk: Ac17PublicKey,
}

/// The assumption size of the pairing in the AC17 scheme.
const ASSUMPTION_SIZE: usize = 2;


/// The setup algorithm of AC17CP and AC17KP. Generates an Ac17PublicKey and an Ac17MasterKey.
///
/// # Examples
///
/// ```
/// use rabe::ac17::*;
///
/// let (_pk, _msk) = ac17::setup();
/// ```
pub fn setup() -> (Ac17PublicKey, Ac17MasterKey) {
    // random number generator
    let _rng = &mut rand::thread_rng();
    // generator of group G1: g and generator of group G2: h
    let _g = G1::random(_rng);
    let _h = G2::random(_rng);
    //pairing
    let _e_gh = pairing(_g, _h);
    // A and B vectors
    let mut _a: Vec<(bn::Fr)> = Vec::new();
    let mut _b: Vec<(bn::Fr)> = Vec::new();
    for _i in 0usize..ASSUMPTION_SIZE {
        _a.push(Fr::random(_rng));
        _b.push(Fr::random(_rng));
    }
    // k vetor
    let mut _k: Vec<(bn::Fr)> = Vec::new();
    for _i in 0usize..(ASSUMPTION_SIZE + 1) {
        _k.push(Fr::random(_rng));
    }
    // h_A vetor
    let mut _h_a: Vec<(bn::G2)> = Vec::new();
    for _i in 0usize..ASSUMPTION_SIZE {
        _h_a.push(_h * _a[_i]);
    }
    _h_a.push(_h);
    // compute the e([k]_1,  [A]_2) term
    let mut _g_k: Vec<(bn::G1)> = Vec::new();
    for _i in 0usize..(ASSUMPTION_SIZE + 1) {
        _g_k.push(_g * _k[_i]);
    }

    let mut _e_gh_ka: Vec<(bn::Gt)> = Vec::new();
    for _i in 0usize..ASSUMPTION_SIZE {
        _e_gh_ka.push(_e_gh.pow(_k[_i] * _a[_i] + _k[ASSUMPTION_SIZE]));
    }

    let _pk = Ac17PublicKey {
        _g: _g,
        _h_a: _h_a,
        _e_gh_ka: _e_gh_ka,
    };
    let _msk = Ac17MasterKey {
        _g: _g,
        _h: _h,
        _g_k: _g_k,
        _a: _a,
        _b: _b,
    };
    // return PK and MSK
    return (_pk, _msk);
}
/// The keygen algorithm of AC17CP. Generates an Ac17CpSecretKey using a Ac17MasterKey and a set of attributes given as Vec<String>.
///
/// # Examples
///
/// ```
/// let _sk = ac17::keygen(&_msk, &vec![String]);
/// ```
pub fn cp_keygen(msk: &Ac17MasterKey, attributes: &Vec<String>) -> Option<Ac17CpSecretKey> {
    // if no attibutes or an empty policy
    // maybe add empty msk also here
    if attributes.is_empty() {
        return None;
    }
    // random number generator
    let _rng = &mut rand::thread_rng();
    // pick randomness
    let mut _r: Vec<(bn::Fr)> = Vec::new();
    let mut _sum = Fr::zero();
    for _i in 0usize..ASSUMPTION_SIZE {
        let _rand = Fr::random(_rng);
        _r.push(_rand);
        _sum = _sum + _rand;
    }
    // first compute Br as it will be used later
    let mut _br: Vec<(bn::Fr)> = Vec::new();
    for _i in 0usize..ASSUMPTION_SIZE {
        _br.push(msk._b[_i] * _r[_i])
    }
    _br.push(_sum);
    // now computer [Br]_2
    let mut _k_0: Vec<(bn::G2)> = Vec::new();
    for _i in 0usize..(ASSUMPTION_SIZE + 1) {
        _k_0.push(msk._h * _br[_i])
    }
    // compute [W_1 Br]_1, ...
    let mut _k: Vec<(String, Vec<(bn::G1)>)> = Vec::new();
    let _a = msk._a.clone();
    let _g = msk._g.clone();
    for _attr in attributes {
        let mut _key: Vec<(bn::G1)> = Vec::new();
        let _sigma_attr = Fr::random(_rng);
        for _t in 0usize..ASSUMPTION_SIZE {
            let mut _prod = G1::zero();
            let _a_t = _a[_t].inverse().unwrap();
            for _l in 0usize..(ASSUMPTION_SIZE + 1) {
                let _hash = combine_three_strings(_attr, _l, _t);
                _prod = _prod + (blake2b_hash_g1(msk._g, &_hash) * (_br[_l] * _a_t));
            }
            _prod = _prod + (msk._g * (_sigma_attr * _a_t));
            _key.push(_prod);
        }
        _key.push(msk._g * _sigma_attr.neg());
        _k.push((_attr.to_string(), _key));
    }
    // compute [k + VBr]_1
    let mut _k_p: Vec<(bn::G1)> = Vec::new();
    let _g_k = msk._g_k.clone();
    let _sigma = Fr::random(_rng);
    for _t in 0usize..ASSUMPTION_SIZE {
        let mut _prod = _g_k[_t];
        let _a_t = _a[_t].inverse().unwrap();
        for _l in 0usize..(ASSUMPTION_SIZE + 1) {
            let _hash = combine_three_strings(&String::from("01"), _l, _t);
            _prod = _prod + (blake2b_hash_g1(msk._g, &_hash) * (_br[_l] * _a_t));
        }
        _prod = _prod + (msk._g * (_sigma * _a_t));
        _k_p.push(_prod);
    }
    _k_p.push(_g_k[ASSUMPTION_SIZE] + (msk._g * _sigma.neg()));
    return Some(Ac17CpSecretKey {
        _attr: attributes.clone(),
        _sk: Ac17SecretKey {
            _k_0: _k_0,
            _k: _k,
            _k_p: _k_p,
        },
    });
}

/// The encrypt algorithm of AC17CP. Generates an Ac17CpCiphertext using a Ac17PublicKey, an access policy given as String and some plaintext data given as [u8].
///
/// # Examples
///
/// ```
/// let _ct = ac17::encrypt(&_pk, &String, &[u8]);
/// ```
pub fn cp_encrypt(
    pk: &Ac17PublicKey,
    policy: &String,
    plaintext: &[u8],
) -> Option<Ac17CpCiphertext> {
    // random number generator
    let _rng = &mut rand::thread_rng();
    // an msp policy from the given String
    let msp: AbePolicy = AbePolicy::from_string(&policy).unwrap();
    let _num_cols = msp._m[0].len();
    let _num_rows = msp._m.len();
    // pick randomness
    let mut _s: Vec<(bn::Fr)> = Vec::new();
    let mut _sum = Fr::zero();
    for _i in 0usize..ASSUMPTION_SIZE {
        let _rand = Fr::random(_rng);
        _s.push(_rand);
        _sum = _sum + _rand;
    }
    // compute the [As]_2 term
    let mut _c_0: Vec<(bn::G2)> = Vec::new();
    let _h_a = pk._h_a.clone();
    for _i in 0usize..ASSUMPTION_SIZE {
        _c_0.push(_h_a[_i] * _s[_i]);
    }
    _c_0.push(_h_a[ASSUMPTION_SIZE] * _sum);
    // compute the [(V^T As||U^T_2 As||...) M^T_i + W^T_i As]_1 terms
    // pre-compute hashes
    let mut _hash_table: Vec<Vec<Vec<(bn::G1)>>> = Vec::new();
    for _j in 0usize.._num_cols {
        let mut _x: Vec<Vec<(bn::G1)>> = Vec::new();
        let _hash1 = combine_two_strings(&String::from("0"), (_j + 1));
        for _l in 0usize..(ASSUMPTION_SIZE + 1) {
            let mut _y: Vec<(bn::G1)> = Vec::new();
            let _hash2 = combine_two_strings(&_hash1, _l);
            for _t in 0usize..ASSUMPTION_SIZE {
                let _hash3 = combine_two_strings(&_hash2, _t);
                let _hashed_value = blake2b_hash_g1(pk._g, &_hash3);
                _y.push(_hashed_value);
            }
            _x.push(_y)
        }
        _hash_table.push(_x);
    }
    let mut _c: Vec<(String, Vec<bn::G1>)> = Vec::new();
    for _i in 0usize.._num_rows {
        let mut _ct: Vec<bn::G1> = Vec::new();
        for _l in 0usize..(ASSUMPTION_SIZE + 1) {
            let mut _prod = G1::zero();
            for _t in 0usize..ASSUMPTION_SIZE {
                let _hash = combine_three_strings(&msp._pi[_i], _l, _t);
                let mut _prod1 = blake2b_hash_g1(pk._g, &_hash);
                for _j in 0usize.._num_cols {
                    if msp._m[_i][_j] == 1 {
                        _prod1 = _prod1 + _hash_table[_j][_l][_t];
                    } else if msp._m[_i][_j] == -1 {
                        _prod1 = _prod1 - _hash_table[_j][_l][_t];
                    }
                }
                _prod = _prod + (_prod1 * _s[_t]);
            }
            _ct.push(_prod);
        }
        _c.push((msp._pi[_i].to_string(), _ct));
    }
    let mut _c_p = Gt::one();
    for _i in 0usize..ASSUMPTION_SIZE {
        _c_p = _c_p * (pk._e_gh_ka[_i].pow(_s[_i]));
    }
    // random msg
    let _msg = pairing(G1::random(_rng), G2::random(_rng));
    _c_p = _c_p * _msg;

    //Encrypt plaintext using derived key from secret
    let mut sha = Sha3::sha3_256();
    match encode(&_msg, Infinite) {
        Err(_) => return None,
        Ok(e) => {
            sha.input(e.to_hex().as_bytes());
            let mut key: [u8; 32] = [0; 32];
            sha.result(&mut key);
            let mut iv: [u8; 16] = [0; 16];
            _rng.fill_bytes(&mut iv);
            return Some(Ac17CpCiphertext {
                _policy: policy.clone(),
                _ct: Ac17Ciphertext {
                    _c_0: _c_0,
                    _c: _c,
                    _c_p: _c_p,
                    _ct: encrypt_aes(&plaintext, &key, &iv).ok().unwrap(),
                    _iv: iv,
                },
            });
        }
    }
}

/// The decrypt algorithm of AC17CP. Reconstructs the original plaintext data as Vec<u8>, given a Ac17CpCiphertext with a matching Ac17CpSecretKey.
///
/// # Examples
///
/// ```
/// let _data = ac17::decrypt(&_sk, &_ct);
/// ```
pub fn cp_decrypt(sk: &Ac17CpSecretKey, ct: &Ac17CpCiphertext) -> Option<Vec<u8>> {
    if traverse_str(&sk._attr, &ct._policy) == false {
        println!("Error: attributes in sk do not match policy in ct.");
        return None;
    } else {
        let _pruned = calc_pruned_str(&sk._attr, &ct._policy);
        println!(
            "pruned attributes: {:?} ",
            calc_pruned_str(&sk._attr, &ct._policy).unwrap().1
        );

        match _pruned {
            None => {
                println!("Error: attributes in sk do not match policy in ct.");
                return None;
            }
            Some(_p) => {
                let (_match, _list) = _p;
                if _match {
                    let mut _prod1_gt = Gt::one();
                    let mut _prod2_gt = Gt::one();
                    for _i in 0usize..(ASSUMPTION_SIZE + 1) {
                        let mut _prod_h = G1::zero();
                        let mut _prod_g = G1::zero();
                        for _current in _list.iter() {
                            for _attr in ct._ct._c.iter() {
                                if _attr.0 == _current.to_string() {
                                    _prod_g = _prod_g + _attr.1[_i];
                                }
                            }
                            for _attr in sk._sk._k.iter() {
                                if _attr.0 == _current.to_string() {
                                    _prod_h = _prod_h + _attr.1[_i];
                                }
                            }
                        }
                        _prod1_gt = _prod1_gt * pairing(sk._sk._k_p[_i] + _prod_h, ct._ct._c_0[_i]);
                        _prod2_gt = _prod2_gt * pairing(_prod_g, sk._sk._k_0[_i]);
                    }
                    let _msg = ct._ct._c_p * (_prod2_gt * _prod1_gt.inverse());
                    // Decrypt plaintext using derived secret from cp-abe scheme
                    let mut sha = Sha3::sha3_256();
                    match encode(&_msg, Infinite) {
                        Err(_) => return None,
                        Ok(e) => {
                            sha.input(e.to_hex().as_bytes());
                            let mut key: [u8; 32] = [0; 32];
                            sha.result(&mut key);
                            let aes = decrypt_aes(&ct._ct._ct[..], &key, &ct._ct._iv)
                                .ok()
                                .unwrap();
                            return Some(aes);
                        }
                    }
                } else {
                    println!("Error: attributes in sk do not match policy in ct.");
                    return None;
                }

            }
        }
    }
}



pub fn kp_keygen(msk: &Ac17MasterKey, policy: &String) -> Option<Ac17KpSecretKey> {
    // random number generator
    let _rng = &mut rand::thread_rng();
    // an msp policy from the given String
    let msp: AbePolicy = AbePolicy::from_string(&policy).unwrap();
    let _num_cols = msp._m[0].len();
    let _num_rows = msp._m.len();
    // pick randomness
    let mut _r: Vec<(bn::Fr)> = Vec::new();
    let mut _sum = Fr::zero();
    for _i in 0usize..ASSUMPTION_SIZE {
        let _rand = Fr::random(_rng);
        _r.push(_rand);
        _sum = _sum + _rand;
    }
    // first compute Br as it will be used later
    let mut _br: Vec<(bn::Fr)> = Vec::new();
    for _i in 0usize..ASSUMPTION_SIZE {
        _br.push(msk._b[_i] * _r[_i])
    }
    _br.push(_sum);
    // now computer [Br]_2
    let mut _k_0: Vec<(bn::G2)> = Vec::new();
    for _i in 0usize..(ASSUMPTION_SIZE + 1) {
        _k_0.push(msk._h * _br[_i])
    }
    let mut _sigma_prime: Vec<(bn::Fr)> = Vec::new();
    for _i in 0usize..(_num_cols - 1) {
        _sigma_prime.push(Fr::random(_rng))
    }
    // compute [W_1 Br]_1, ...
    let mut _k: Vec<(String, Vec<(bn::G1)>)> = Vec::new();
    let _a = msk._a.clone();
    let _g = msk._g.clone();
    for _i in 0usize.._num_rows {
        let mut _key: Vec<(bn::G1)> = Vec::new();
        let _sigma_attr = Fr::random(_rng);
        // calculate _sk_i1 and _sk_i2 terms
        for _t in 0usize..ASSUMPTION_SIZE {
            let mut _prod = G1::zero();
            let _a_t = _a[_t].inverse().unwrap();
            for _l in 0usize..(ASSUMPTION_SIZE + 1) {
                let _hash = combine_three_strings(&msp._pi[_i], _l, _t);
                _prod = _prod + (blake2b_hash_g1(msk._g, &_hash) * (_br[_l] * _a_t));
            }
            _prod = _prod + (msk._g * (_sigma_attr * _a_t));
            if msp._m[_i][0] == 1 {
                _prod = _prod + (msk._g_k[_t]);
            } else if msp._m[_i][0] == -1 {
                _prod = _prod - (msk._g_k[_t]);
            }
            let mut _temp = G1::zero();
            for _j in 1usize.._num_cols {
                // sum term of _sk_it
                let _hash0 = combine_two_strings(&String::from("0"), _j);
                for _l in 0usize..(ASSUMPTION_SIZE + 1) {
                    let _hash1 = combine_three_strings(&_hash0, _l, _t);
                    _temp = _temp + (blake2b_hash_g1(msk._g, &_hash1) * (_br[_l] * _a_t));
                }
                _temp = _temp + (msk._g * _sigma_prime[_j - 1].neg());
                if msp._m[_i][_j] == 1 {
                    _prod = _prod + _temp;
                } else if msp._m[_i][_j] == -1 {
                    _prod = _prod - _temp;
                }
            }
            _key.push(_prod);
        }
        // calculate _sk_i3 term
        let mut _sk_i3 = msk._g * _sigma_attr.neg();
        if msp._m[_i][0] == 1 {
            _sk_i3 = _sk_i3 + (msk._g_k[ASSUMPTION_SIZE]);
        } else if msp._m[_i][0] == -1 {
            _sk_i3 = _sk_i3 - (msk._g_k[ASSUMPTION_SIZE]);
        }
        // sum term of _sk_i3
        for _j in 1usize.._num_cols {
            if msp._m[_i][_j] == 1 {
                _sk_i3 = _sk_i3 + (msk._g * _sigma_prime[_j - 1].neg());
            } else if msp._m[_i][_j] == -1 {
                _sk_i3 = _sk_i3 - (msk._g * _sigma_prime[_j - 1].neg());
            }
        }
        _key.push(_sk_i3);
        _k.push((msp._pi[_i].to_string(), _key));
    }
    return Some(Ac17KpSecretKey {
        _policy: policy.clone(),
        _sk: Ac17SecretKey {
            _k_0: _k_0,
            _k: _k,
            _k_p: Vec::new(),
        },
    });
}

pub fn kp_encrypt(
    pk: &Ac17PublicKey,
    attributes: &Vec<String>,
    plaintext: &[u8],
) -> Option<Ac17KpCiphertext> {
    // random number generator
    let _rng = &mut rand::thread_rng();
    // pick randomness
    let mut _s: Vec<(bn::Fr)> = Vec::new();
    let mut _sum = Fr::zero();
    for _i in 0usize..ASSUMPTION_SIZE {
        let _rand = Fr::random(_rng);
        _s.push(_rand);
        _sum = _sum + _rand;
    }
    // compute the [As]_2 term
    let mut _c_0: Vec<(bn::G2)> = Vec::new();
    let _h_a = pk._h_a.clone();
    for _i in 0usize..ASSUMPTION_SIZE {
        _c_0.push(_h_a[_i] * _s[_i]);
    }
    _c_0.push(_h_a[ASSUMPTION_SIZE] * _sum);
    // compute ct_y terms
    let mut _c: Vec<(String, Vec<bn::G1>)> = Vec::new();
    for _attr in attributes {
        let mut _ct: Vec<bn::G1> = Vec::new();
        for _l in 0usize..(ASSUMPTION_SIZE + 1) {
            let mut _prod = G1::zero();
            for _t in 0usize..ASSUMPTION_SIZE {
                let _hash = combine_three_strings(&_attr, _l, _t);
                let mut _prod1 = blake2b_hash_g1(pk._g, &_hash);
                _prod = _prod + (_prod1 * _s[_t]);
            }
            _ct.push(_prod);
        }
        _c.push((_attr.to_string(), _ct));
    }
    let mut _c_p = Gt::one();
    for _i in 0usize..ASSUMPTION_SIZE {
        _c_p = _c_p * (pk._e_gh_ka[_i].pow(_s[_i]));
    }
    // random msg
    let _msg = pairing(G1::random(_rng), G2::random(_rng));
    _c_p = _c_p * _msg;
    //Encrypt plaintext using derived key from secret
    let mut sha = Sha3::sha3_256();
    match encode(&_msg, Infinite) {
        Err(_) => return None,
        Ok(e) => {
            sha.input(e.to_hex().as_bytes());
            let mut key: [u8; 32] = [0; 32];
            sha.result(&mut key);
            let mut iv: [u8; 16] = [0; 16];
            _rng.fill_bytes(&mut iv);
            return Some(Ac17KpCiphertext {
                _attr: attributes.clone(),
                _ct: Ac17Ciphertext {
                    _c_0: _c_0,
                    _c: _c,
                    _c_p: _c_p,
                    _ct: encrypt_aes(&plaintext, &key, &iv).ok().unwrap(),
                    _iv: iv,
                },
            });
        }
    }
}

/// The decrypt algorithm of AC17KP. Reconstructs the original plaintext data as Vec<u8>, given a Ac17KpCiphertext with a matching Ac17KpSecretKey.
///
/// # Examples
///
/// ```
/// let _data = ac17::decrypt(&_sk, &_ct);
/// ```
pub fn kp_decrypt(sk: &Ac17KpSecretKey, ct: &Ac17KpCiphertext) -> Option<Vec<u8>> {
    if traverse_str(&ct._attr, &sk._policy) == false {
        println!("Error: attributes in ct do not match policy in sk.");
        return None;
    } else {
        let _pruned = calc_pruned_str(&ct._attr, &sk._policy);
        println!(
            "pruned attributes: {:?} ",
            calc_pruned_str(&ct._attr, &sk._policy).unwrap().1
        );
        match _pruned {
            None => {
                println!("Error: attributes in sk do not match policy in ct.");
                return None;
            }
            Some(_p) => {
                let (_match, _list) = _p;
                if _match {
                    let mut _prod1_gt = Gt::one();
                    let mut _prod2_gt = Gt::one();
                    for _i in 0usize..(ASSUMPTION_SIZE + 1) {
                        let mut _prod_h = G1::zero();
                        let mut _prod_g = G1::zero();
                        for _current in _list.iter() {
                            for _attr in ct._ct._c.iter() {
                                if _attr.0 == _current.to_string() {
                                    _prod_g = _prod_g + _attr.1[_i];
                                }
                            }
                            for _attr in sk._sk._k.iter() {
                                if _attr.0 == _current.to_string() {
                                    _prod_h = _prod_h + _attr.1[_i];
                                }
                            }
                        }
                        // for _j in 0usize..ct._ct._c.len() {
                        //     _prod_h = _prod_h + sk._sk._k[_j].1[_i];
                        //     _prod_g = _prod_g + ct._ct._c[_j].1[_i];
                        // }
                        _prod1_gt = _prod1_gt * pairing(_prod_h, ct._ct._c_0[_i]);
                        _prod2_gt = _prod2_gt * pairing(_prod_g, sk._sk._k_0[_i]);
                    }
                    let _msg = ct._ct._c_p * (_prod2_gt * _prod1_gt.inverse());
                    // Decrypt plaintext using derived secret from cp-abe scheme
                    let mut sha = Sha3::sha3_256();
                    match encode(&_msg, Infinite) {
                        Err(_) => return None,
                        Ok(e) => {
                            sha.input(e.to_hex().as_bytes());
                            let mut key: [u8; 32] = [0; 32];
                            sha.result(&mut key);
                            let aes = decrypt_aes(&ct._ct._ct[..], &key, &ct._ct._iv)
                                .ok()
                                .unwrap();
                            return Some(aes);
                        }
                    }
                } else {
                    println!("Error: attributes in sk do not match policy in ct.");
                    return None;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn ac17kp_and() {
        // setup scheme
        let (pk, msk) = setup();
        // our plaintext
        let plaintext = String::from("dance like no one's watching, encrypt like everyone is!")
            .into_bytes();
        // our policy
        let policy = String::from(r#"{"AND": [{"ATT": "A"}, {"ATT": "B"}]}"#);
        // kp-abe ciphertext
        let ct: Ac17KpCiphertext =
            kp_encrypt(&pk, &vec!["A".to_string(), "B".to_string()], &plaintext).unwrap();
        // a kp-abe SK key
        let sk: Ac17KpSecretKey = kp_keygen(&msk, &policy).unwrap();
        // and now decrypt again
        assert_eq!(kp_decrypt(&sk, &ct).unwrap(), plaintext);
    }

    #[test]
    fn ac17kp_or_and() {
        // setup scheme
        let (pk, msk) = setup();
        // our plaintext
        let plaintext = String::from("dance like no one's watching, encrypt like everyone is!")
            .into_bytes();
        // our policy
        let policy = String::from(r#"{"OR": [{"AND": [{"ATT": "A"}, {"ATT": "B"}]}, {"AND": [{"ATT": "C"}, {"ATT": "D"}]}]}"#);
        // kp-abe ciphertext
        let ct: Ac17KpCiphertext =
            kp_encrypt(&pk, &vec!["A".to_string(), "B".to_string()], &plaintext).unwrap();
        // a kp-abe SK key
        let sk: Ac17KpSecretKey = kp_keygen(&msk, &policy).unwrap();
        // and now decrypt again
        assert_eq!(kp_decrypt(&sk, &ct).unwrap(), plaintext);
        // kp-abe ciphertext
        let ct: Ac17KpCiphertext =
            kp_encrypt(&pk, &vec!["C".to_string(), "D".to_string()], &plaintext).unwrap();
        // a kp-abe SK key
        let sk: Ac17KpSecretKey = kp_keygen(&msk, &policy).unwrap();
        // and now decrypt again
        assert_eq!(kp_decrypt(&sk, &ct).unwrap(), plaintext);
    }

    #[test]
    fn ac17kp_or() {
        // setup scheme
        let (pk, msk) = setup();
        // our plaintext
        let plaintext = String::from("dance like no one's watching, encrypt like everyone is!")
            .into_bytes();
        // our policy
        let policy = String::from(r#"{"OR": [{"ATT": "A"}, {"ATT": "B"}]}"#);
        // kp-abe ciphertext
        let ct: Ac17KpCiphertext = kp_encrypt(&pk, &vec!["B".to_string()], &plaintext).unwrap();
        // a kp-abe SK key
        let sk: Ac17KpSecretKey = kp_keygen(&msk, &policy).unwrap();
        // and now decrypt again
        assert_eq!(kp_decrypt(&sk, &ct).unwrap(), plaintext);
    }


    #[test]
    fn ac17cp_and() {
        // setup scheme
        let (pk, msk) = setup();
        // our plaintext
        let plaintext = String::from("dance like no one's watching, encrypt like everyone is!")
            .into_bytes();
        // our policy
        let policy = String::from(r#"{"AND": [{"ATT": "A"}, {"ATT": "B"}]}"#);
        // kp-abe ciphertext
        let ct: Ac17CpCiphertext = cp_encrypt(&pk, &policy, &plaintext).unwrap();
        // a kp-abe SK key
        let sk: Ac17CpSecretKey = cp_keygen(&msk, &vec!["A".to_string(), "B".to_string()]).unwrap();
        // and now decrypt again
        assert_eq!(cp_decrypt(&sk, &ct).unwrap(), plaintext);
    }

    #[test]
    fn ac17cp_or() {
        // setup scheme
        let (pk, msk) = setup();
        // our plaintext
        let plaintext = String::from("dance like no one's watching, encrypt like everyone is!")
            .into_bytes();
        // our policy
        let policy = String::from(r#"{"OR": [{"ATT": "A"}, {"ATT": "B"}, {"ATT": "C"}]}"#);
        // kp-abe ciphertext
        let ct: Ac17CpCiphertext = cp_encrypt(&pk, &policy, &plaintext).unwrap();
        // a matching kp-abe SK key
        let sk_m1: Ac17CpSecretKey = cp_keygen(&msk, &vec!["A".to_string()]).unwrap();
        // a matching kp-abe SK key
        let sk_m2: Ac17CpSecretKey = cp_keygen(&msk, &vec!["B".to_string()]).unwrap();
        // a matching kp-abe SK key
        let sk_nm: Ac17CpSecretKey = cp_keygen(&msk, &vec!["D".to_string()]).unwrap();
        // and now decrypt again
        assert_eq!(cp_decrypt(&sk_m1, &ct).unwrap(), plaintext);
        // and now decrypt again
        assert_eq!(cp_decrypt(&sk_m2, &ct).unwrap(), plaintext);
        // and now decrypt again
        assert_eq!(cp_decrypt(&sk_nm, &ct).is_none(), true);
    }

    #[test]
    fn ac17cp_or_and_and() {
        // setup scheme
        let (pk, msk) = setup();
        // our plaintext
        let plaintext = String::from("dance like no one's watching, encrypt like everyone is!")
            .into_bytes();
        // our policy
        let policy = String::from(r#"{"OR": [{"AND": [{"ATT": "A"}, {"ATT": "B"}]}, {"AND": [{"ATT": "C"}, {"ATT": "D"}]}]}"#);
        // kp-abe ciphertext
        let ct: Ac17CpCiphertext = cp_encrypt(&pk, &policy, &plaintext).unwrap();
        // a kp-abe SK key
        let sk: Ac17CpSecretKey = cp_keygen(
            &msk,
            &vec![
                "A".to_string(),
                "B".to_string(),
                "C".to_string(),
                "D".to_string(),
            ],
        ).unwrap();
        // and now decrypt again
        assert_eq!(cp_decrypt(&sk, &ct).unwrap(), plaintext);
    }
}
