pub fn help(query: &[&str], screen: &::frontend::Screen) {
    let all = query.is_empty();

    if all || query.contains(&"ban") || query.contains(&"unban") {
        screen.log("\
            ban/unban <user>\n\
            A ban prevents logging in as <user> and prevents creation of accounts on their IP.\
        ".to_string());
    }
    if all || query.contains(&"connect") {
        let mut text = String::from("\
            connect <ip[:port]>\n\
            Connects to IP. Default port is \
        ");
        text.push_str(&::common::DEFAULT_PORT.to_string());
        text.push('.');
        screen.log(text);
    }
    if all || query.contains(&"create") {
        screen.log("\
            create <\"channel\"/\"group\"> <name> [data]\n\
            Creates a channel/group with <name>.\n\
            If it's a group, it may optionally take [data] as a permission string\n\
            to prevent having to edit it later.\
        ".to_string());
    }
    if all || query.contains(&"delete") {
        screen.log("\
            delete <\"channel\"/\"group\"/\"message\"> <id>\n\
            Delets channel/group with <id>.\
        ".to_string());
    }
    if all || query.contains(&"disconnect") {
        screen.log("\
            disconnect\n\
            Disconnects from the currently connected server.\
        ".to_string());
    }
    if all || query.contains(&"forget") {
        screen.log("\
            forget <ip[:port]>\n\
            Forgets all data about the server on <ip[:port]>.\n\
            Useful if the server was reset.\
        ".to_string());
    }
    if all || query.contains(&"help") {
        screen.log("\
            help [command1 [command2 [etc...]]]\n\
            Prints help about one or more commands.\n\
            If left empty, it shows all of them.\
        ".to_string());
    }
    if all || query.contains(&"info") {
        screen.log("\
            info <channel/group/user>\n\
            Prints info about <channel/group/user> based on name.\n\
            Useful for getting the ID for functions that require such.\
        ".to_string());
    }
    if all || query.contains(&"join") {
        screen.log("\
            join <channel>\n\
            Joins <channel> and prints out recent messages.\
        ".to_string());
    }
    if all || query.contains(&"list") {
        screen.log("\
            list <\"channels\"/\"groups\"/\"users\">\n\
            Lists all <\"channels\"/\"groups\"/\"users\">.\
        ".to_string());
    }
    if all || query.contains(&"msg") {
        screen.log("\
            msg <user> <message>\n\
            Sends <message> in encrypted form privately to <user>.\n\
            See /setupkeys.\
        ".to_string());
    }
    if all || query.contains(&"nick") {
        screen.log("\
            nick <name>\n\
            Changes the nickname to <name>.\n\
            If you are connected to a server, it also changes nickname on that server.\n\
            It does *not* update all of your servers.\
        ".to_string());
    }
    if all || query.contains(&"passwd") {
        screen.log("\
            passwd\n\
            Changes password on the current server.\
        ".to_string());
    }
    if all || query.contains(&"quit") {
        screen.log("\
            quit\n\
            Quits the application.\
        ".to_string());
    }
    if all || query.contains(&"setupkeys") {
        screen.log("\
            setupkeys <user>\n\
            Prepares for encrypted messaging with /msg.\
        ".to_string());
    }
    if all || query.contains(&"update") {
        screen.log("\
            update <\"channel\"/\"group\"> <id>\n\
            Interactively edits <\"channel\"/\"group\"> with <id>.\
        ".to_string());
    }
}
