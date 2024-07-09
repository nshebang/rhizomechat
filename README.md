# rhizomechat

rhizomechat is an extremely simple [web0](https://web0.small-web.org/) chat
software that doesn't require client-side javascript to
work. It's inspired by old CGI chat software like comchat. The main working
instance is the one maintained by the Spanish-speaking project,
[ichoria.org](https://chat.ichoria.org)

## how to install

Please note that this software is not project-agnostic out of the box. You may
need to make some minor modifications to the HTML and CSS source files to adapt
the software to your project.

1. Make sure you have Git, NodeJS and pm2 installed
2. Create two important files in the root directory:
`touch banned-ips.txt banned-words.txt`
3. Copy `config.template.json` to `config.json`
4. Change the default insecure "staff" credentials in config.json (IMPORTANT!)
5. Generate the "secretKey" by running `openssl rand -hex 64` and copying the
resulting string to config.json
6. Add some emotes if you want to /public/img/emotes and then run
`npm run exportEmotes` to automatically add them to config.json
7. Run `npm run devStart` to test the software or `npm start` to start it in
production mode using pm2

You don't need to set up a database or some other nonsense. It's all
plain text files.

After you run the software you can join your chat as admin by typing
`yourname##adminpassword` in the name field. Please note that you must add
at least one administrator account to config.json first.

You may need to use nginx or some reverse proxy software to actually make 
your chat accesible through the internet.

## license

rhizomechat is available under the terms of the
[GNU AGPL 3.0](https://www.gnu.org/licenses/agpl-3.0.en.html) license.

