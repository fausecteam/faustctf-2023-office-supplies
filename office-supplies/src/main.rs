pub mod db;
pub mod query;
pub mod tables;
pub mod types;

extern crate libc;
extern crate rand;

use std::process::Command;

use query::{Query, UpdateQuery};

type Users = ((String, String), String);
type Products = (String, ((String, i64), Box<[u8]>));
type BugReport = ((String, i64), Box<[u8]>);

fn input() -> String {
    use std::io::Write;
    std::io::stdout().flush().unwrap();
    let stdin = std::io::stdin();
    let mut buf = String::new();
    stdin.read_line(&mut buf).unwrap();

    match buf.pop() {
        Some('\n') => {
            // Remove newline
            buf
        }
        Some(x) => {
            // Keep if not newline
            buf.push(x);
            buf
        }
        None => {
            // EOF
            std::process::exit(0);
        }
    }
}

fn read_blueprint() -> Option<Box<[u8]>> {
    use std::io::{Read, Write};
    let mut stdin = std::io::stdin();
    print!("Blueprint Length (hex): ");
    let length = match input().parse::<usize>() {
        Ok(l) => l,
        Err(_) => return None,
    };
    print!("Blueprint Data (hex): ");
    std::io::stdout().flush().unwrap();
    let mut c = 0u8;
    let mut data = Vec::with_capacity(length);
    loop {
        unsafe {
            stdin
                .read(std::slice::from_raw_parts_mut(&mut c, 1))
                .unwrap();
            if c == '\n' as u8 {
                break;
            }
            let a = c;
            stdin
                .read_exact(std::slice::from_raw_parts_mut(&mut c, 1))
                .unwrap();
            data.push(
                ((a as char).to_digit(16).expect("Invalid hex") * 16
                    + (c as char).to_digit(16).expect("Invalid hex")) as u8,
            );
        }
        if data.len() > 8192 {
            println!("!!! Blueprint too long !!!");
            return None;
        }
    }
    Some(data.into_boxed_slice())
}

struct HexWrapper<'a>(&'a [u8]);

impl<'a> std::fmt::Display for HexWrapper<'a> {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        for c in self.0 {
            write!(fmt, "{:02x}", c)?;
        }
        Ok(())
    }
}

fn menu(options: &'static str) -> Option<i64> {
    print!("\n{}\n> ", options);

    input().parse().ok()
}

fn register<U: Clone + Eq + std::hash::Hash, P: Fn(&Users) -> &U>(
    db: &mut db::Database<Users, U, P>,
) -> Option<String> {
    println!("Creating new account...");
    print!("Username: ");
    let user = input();
    if user.len() >= 40 {
        println!("!!! Username too long !!!");
        return None;
    }
    print!("Password: ");
    let password = input();
    if password.len() >= 100 {
        println!("!!! Password too long !!!");
        return None;
    }
    print!("Payment Info: ");
    let payment = input();
    if payment.len() >= 200 {
        println!("!!! Payment Info too long !!!");
        return None;
    }
    if db.insert(((user.clone(), password), payment.clone())) {
        println!(
            "\nHello {}. Welcome to the future of marketplace logistics.\nYour purchases will be automatically deducted from your payment info {}. Your money is safe with our blazingly fast and memory safe application",
            user, payment
        );
        Some(user)
    } else {
        println!("!!! User already exists !!!");
        None
    }
}

fn login<U: Clone + Eq + std::hash::Hash, P: Fn(&Users) -> &U>(
    db: &mut db::Database<Users, U, P>,
) -> Option<String> {
    print!("Username: ");
    let user = input();
    print!("Password: ");
    let password = input();
    if let Some(payment) = db
        .query()
        .filter(|((name, pw), _)| name == &user && pw == &password)
        .select(|(_, payment)| payment)
        .execute()
        .next()
    {
        println!(
            "\nHello {}. Welcome to the future of marketplace logistics.\nYour purchases will be automatically deducted from your payment info {}. Your money is safe with our blazingly fast and memory safe application",
            user, payment
        );

        Some(user)
    } else {
        println!("!!! No such login !!!");
        None
    }
}

fn account() -> String {
    let mut users = db::Database::<Users, _, _>::new("data/user.db", |(user, _)| user)
        .expect("Failed to open database");

    loop {
        print!("1. Register\n2. Login\n> ");
        match input().trim().parse::<i64>() {
            Ok(1) => {
                if let Some(user) = register(&mut users) {
                    return user;
                }
            }
            Ok(2) => {
                if let Some(user) = login(&mut users) {
                    return user;
                }
            }
            _ => {
                println!("Invalid choice");
            }
        }
        println!();
    }
}

fn random_quote() -> String {
    unsafe {
        String::from_utf8_unchecked(
            Command::new("bash")
                .args(["-c", "shuf -n 1 /app/quotes.txt | tr -d '\n'"])
                .output()
                .expect("Failed to get random quote")
                .stdout,
        )
    }
}

fn quotes() {
    let users = db::Database::<Users, _, _>::new_readonly("data/user.db", |(user, _)| user)
        .expect("Failed to open database");

    println!("Here is what our dear users say about this service:");
    for username in users
        .query()
        .select(|((username, _), _)| username)
        .execute()
    {
        println!("{}: {}", username, random_quote());
    }
}

fn report_bug<U: Clone + std::hash::Hash + Eq, V: Fn(&BugReport) -> &U>(
    user: &str,
    db: &mut db::Database<BugReport, U, V>,
    current_bugreport: &mut Option<Box<[u8]>>,
) {
    loop {
        match menu("1. List Reports\n2. Show Report\n3. Edit Report\n4. Submit Report\n5. Return to main menu") {
            Some(1) => {
                println!("+----------------------+------------------------------------------+");
                println!("| {:20} | {:40} |", "Id", "Content");
                println!("+----------------------+------------------------------------------+");
                for (id, data) in db
					.query()
                    .filter(|((u, _), _)| u == user)
                    .select(|((_, id), data)| (id, data))
                    .execute()
                {
                    let mut data = std::str::from_utf8(&data[..40]).expect("Invalid UTF-8");
					if let Some((a, _)) = data.split_once('\n') {
						data = a;
					}
                    println!("| {:20} | {:40} |", id, data);
                    println!("+----------------------+------------------------------------------+");
                }
            }
            Some(2) => {
                println!(
                    "Current Report: {}",
                    current_bugreport
                        .as_ref()
                        .map(|x| std::str::from_utf8(&**x).expect("Invalid UTF-8"))
                        .unwrap_or("(none)")
                );
			}
			Some(3) => {
                let buf: &mut [u8] = current_bugreport
                    .get_or_insert_with(|| {
						println!("No active bug report found. Creating new one...");
                        println!("Size: ");
                        let size: usize = match input().parse() {
                            Ok(c) if c > 0 && c < 1024 => c,
                            _ => {
                                panic!("Invalid size");
                            }
                        };
                        let mut v = Vec::new();
                        v.resize(size, 0u8);
                        v.into_boxed_slice()
                    })
                    .as_mut();
                print!("New Content: ");
                use std::io::{Read, Write};
                std::io::stdout().flush().unwrap();
                let mut stdin = std::io::stdin();
                stdin.read(buf).unwrap();
            }
            Some(4) => {
                let max_id = *db
					.query()
                    .filter(|((u, _), _)| u == user)
                    .select(|((_, id), _)| id)
                    .execute()
                    .into_iter()
                    .max()
                    .unwrap_or(&&0);
                if let Some(r) = std::mem::replace(current_bugreport, None) {
                    db.insert(((user.to_string(), max_id + 1), r));
                } else {
                    println!("You have to write a report first!");
                }
            }
            Some(5) => return,
            _ => println!("Invalid choice"),
        }
    }
}

fn drop_privs() {
    use rand::Rng;
    unsafe {
        let uid = rand::thread_rng().gen::<u16>() as u32 + 2000;
        assert!(libc::setgroups(0, std::ptr::null()) == 0);
        assert!(libc::setresgid(uid, uid, uid) == 0);
        assert!(libc::setresuid(uid, uid, uid) == 0);
        assert!(
            libc::setrlimit(
                libc::RLIMIT_NPROC,
                &libc::rlimit {
                    rlim_cur: 50,
                    rlim_max: 50,
                }
            ) == 0
        );
    }
}

fn main() {
    let user = account();

    unsafe {
        // Created files must be readable + writeable by randomized user ids
        libc::umask(0);
    }

    let mut products =
        db::Database::<Products, _, _>::new("data/product.db", |(_, ((prodname, _), _))| prodname)
            .expect("Failed to open database");

    let mut reports =
        db::Database::<BugReport, _, _>::new("data/bugs.db", |(user_and_id, _)| user_and_id)
            .expect("Failed to open database");

    let mut draft_report = None;

    drop_privs();
    loop {
        match menu(
            "1. List Products\n2. Buy Product\n3. Sell Product\n4. Edit Product\n5. Report a Bug\n6. Hear inspiring stories from our users\n7. Exit",
        ) {
            Some(1) => {
                println!("+------------------------------------------+----------------------+------------------------------------------+");
                println!("| {:40} | {:20} | {:40} |", "Name", "Price", "Seller");
                println!("+------------------------------------------+----------------------+------------------------------------------+");
                for (prod, price, user) in products
                    .query()
                    .select(|(user, ((prod, price), _))| (prod, price, user))
                    .execute()
                    .into_iter()
                {
                    println!("| {:40} | {:20} | {:40} |", prod, price, user);
                    println!("+------------------------------------------+----------------------+------------------------------------------+");
                }
                println!("");
            }
            Some(2) => {
                print!("Product: ");
                let prod = input();
                if let Some((prod, cost, data)) = products
                    .query()
                    .select(|(_, ((p, c), data))| (p, c, data))
                    .filter(|&(p, _, _)| p == &prod)
                    .execute()
                    .next()
                {
                    println!("Thank you for purchasing {}, {}\n", prod, user);
                    println!(
                        "The cost of {} money units will be deducted from your payment info",
                        cost
                    );
                    println!("Here is the blueprint:\n{}", HexWrapper(data));
                } else {
                    println!("No such product!");
                }
            }
            Some(3) => {
                print!("Name: ");
                let name = input();
                if name.len() > 40 {
                    println!("!!! Product name too long !!!");
                    break;
                }
                print!("Cost: ");
                let cost: i64 = match input().parse() {
                    Ok(c) if c >= 0 => c,
                    _ => {
                        println!("Invalid price");
                        break;
                    }
                };
                if let Some(data) = read_blueprint() {
                    if products.insert((user.clone(), ((name, cost), data))) {
                        println!("Product added");
                    } else {
                        println!("!!! Product does already exist !!!");
                    }
                }
            }
            Some(4) => {
                print!("Product: ");
                let prod = input();
                if let Some((u, ((p, c), data))) = products
                    .query()
                    .filter(|&(_, ((p, _), _))| p == &prod)
                    .execute()
                    .next()
                {
                    if u != &user {
                        println!("This product doesn't belong to you!");
                    } else {
                        println!("Product {}, currently costs {} money units and gives the blueprint:\n{}", p, c, HexWrapper(data));

                        print!("New Price: ");
                        let cost: i64 = match input().parse() {
                            Ok(c) if c >= 0 => c,
                            _ => {
                                println!("Invalid price");
                                break;
                            }
                        };

                        if let Some(data) = read_blueprint() {
                            use types::DbType;
                            products
                                .update()
                                .when(|(_, ((p, _), _))| p == &prod)
                                .execute(|(_, ((_, c), b))| {
                                    c.set(&cost);
                                    b.set(&data);
                                });

                            println!("Records updated.");
                        }
                    }
                } else {
                    println!("No such product!");
                }
            }
            Some(5) => report_bug(&user, &mut reports, &mut draft_report),
			Some(6) => quotes(),
			Some(7) => break,
            _ => println!("Invalid choice"),
        };
    }
}
