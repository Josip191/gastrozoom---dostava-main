# GastroZoom - Dostava

 Za pokretanje treba prvo dodati u backend direktoriju .env datoteku i nju upisati
> PORT=4000
> DATABASE_URL="mysql://root:password@localhost:3306/gastrozoom"
> JWT_SECRET="your_jwt_secret"

gdje za umjesto "password" treba staviti "lozinka"

nakon toga unutar backend direktorija u terminalu treba pokrenuti 
> npm install 
za instaliranje node modula koji su potrebni za pokretanje backend servera
>
> unutar package.json se mogu vidjeti ti moduli u "dependencies" i "devDependencies"
> "morgan" je koristen za log ispis backend servera

"express" je framework za backend koji je koristen

"cors" je modul koji omogucuje ili ogranicava zahtjeve sa drugih domena

"prisma" je orm za upravljanje, dodavanje, uredjivanje i brisanje (u biti vrsenje CRUD operacija, sto je skracenica za create, read, update i delete) u bazi podataka na backendu

"bcrypt" je modul koristen za enkripciju i dekripciju lozinke tako da lozinka korisnika bude sifrirana kada se sprema u bazu podataka

"dotenv" sluzi za ucitavanje vrijednosti varijabli definiranih u .env dokumentu

"jsonwebtoken" se koristi za jwt autentifikaciju i autorizaciju korisnika tj. za prijavu korisnika
radi na nacin da u .env dokumentu drzimo kod tj. kljuc kojim on vrsi kreiranje jwt tokena
a onda tim tokenom onda server prepoznaje koji je korisnik u pitanju
kada se loginuje server na osnovu korisnickih podataka tj. user id, user email i user role kreira jwt token koji je zapravo kod kodiran sa JWT_SECRET iz .env datoteke
preko jwt_secret se vrsi kodiranje i dekodiranje tog tokena
tako da onda kada otvorimo neki link kojim moze samo prijavljen korisnik pristupit, browser u zaglavlju (header) daje jwt token a backend onda taj jwt token kad dekodira dobije korisnicke podatke

Pokusat cu primjerom za login objasnit kako to radi
kada se korisnik prijavljuje pokrece rutu koja se nalazi u /backend/routes/auth.js
Na 55. liniji koda je definirana funkcija za login (router.post('/login', async function(req, res) {...)

Na tu rutu daje podatke koje je unio na stranicu email i password

backend onda trazi u bazi podataka korisnika sa tim emailom i uzima podatke tog korisnika

kada ga je pronasao provjerava da li je unesena sifra ista kao u podacima koje je uzeo iz baze podataka

ako jeste onda sa podacima id, email i role korisnika koje je uzeo iz baze podataka sifrira ih koristeci jwt_secret

rezultat sifriranja je token a jwt_secret se onda koristi kao kljuc kojim se iz token mogu desifrirati podaci gdje ce rezultat biti podaci koje je prije sifrirao a to su id, email i role korisnika

"nodemon" je alat za automatsko restartovanja aplikacije kada se izmjeni nesto u kodu




u frontendu je koristen kao glavi framework vue.js sa vuetify
"vue" framework
"vuetify" library za gotove komponente za brze kreiranje izgleda aplikacije

"vue-router" za kreiranje ruta na frontendu tj na osnovu datoteka u /frontend/src/pages u aplikaciji dobivamo za svaku datoteku njen link
npr. za datoteku login.vue dobivamo link na stranici http://<adresa-aplikacije>/login

"pinia" je state management system. sluzi za upravljanje podacima na frontendu koje koriste stranice

"axios" modul s kojim uzimamo i saljemo podatke backendu

u /frontend/src/stores/ su definirane datoteke koje su zasebna skladista od pinia i unutar njih se nalaze takodje funkcije u kojim je koristen axios za uzimanje ili slanje podataka backendu

"@vueuse/core" je modul iz kog koristimo useLocalStorage funkciju
a ta funkcija nam sluzi da spremimo podatke u lokalnu memoriju browsera tj web preglednika za nasu stranicu

u nasem slucaju koristimo useLocalStorage da spremimo jwt token u web preglednik kada se prijavimo
tako stranica prepoznaje da smo prijavljeni
a kad se odjavimo onda se jwt token brise iz lokalne memorije web preglednika

takodjer useLocalStorage u ovoj aplikaciji je koristen za korpu
kada dodamo artikal tj hranu u korpu
id hrane i kolicina koju smo izabrali se sprema u lokalni spremnik browsera
tako da kad ponovo ucitamo stranicu il odemo na neki drugi link
hrana ostaje u korpi

kada promjenimo kolicinu hrane koju uzimamo il uklonimo artikal ti podaci u lokalnom spreminku se mijenjaju

a ako zavrsimo narudzbu podaci o korpi se brisu iz lokalnog spremnika i stranica onda prikazuje da je korpa prazna

znaci za BACKEND su koristeni:
> morgan
> express
> cors
> prisma
> bcrypt
> dotenv
> jsonwebtoken
> nodemon

a za FRONTEND:
> vue
> vuetify
> svi ostali moduli koji dolaze zajedno sa vuetify projektom kada se kreira
> vue-router
> pinia
> axios
> @vueuse/core
> vite

za BAZU PODATAKA je koristen
> MySQL
gdje je MySQL server pokrenut sa
> Docker
koristeci konfiguraciju koja je definirana u docker-compose datoteci
>
> vite" je modul koji sluzi za pokretanje servera dok kreiramo aplikaciju gdje kao i sto nodemon na backendu restartuje server kada dodje do izmjene u kodu tako i vite osvjezi server kada se izmjeni kod
takodjer s njim se moze i koristit build gdje sve datoteke iz frontenda kompajlira u obicni html, css i javascript datoteke koje se onda koriste u produkciji


POKRETANJE PROJEKTA

nakon sto je kreirana .env datoteka u backendu i uneseni podaci koje sam ranije naveo
i nakon sto je pokrenuta npm install komanda na backendu
treba pokrenuti mysql server preko dockera
koristimo naredbu
> docker-compose up --build
>
> kada smo pokrenuli mysql server
ostavimo ga da radi u pozadini a u novom prozoru ili tabu terminala opet u backend direktoriju pokrecemo naredbu
> npx prisma migrate dev

to je naredba koju pokrecemo kada smo prvi put pokrenut mysql server jer jos uvijek nemamo nista u bazi podataka
zato ovom naredbom prisma koristi /backend/prisma/scheme.prisma shemu kojom kreira sve tabele u bazi podataka koje su potrebne za nasu aplikaciju

time smo izvrsili migraciju
i sada mozemo pokrenuti backend server naredbom
> npm run dev
>
>zatim sada trebamo pokrenuti frontend server
u direktoriju frontenda otvorimo terminal i unesemo opet komandu
> npm install

kada smo instalirali sve potrebne module za pokretanje servera
pokrecemo komandu
> npm run dev

i time smo pokrenuli frontend server tako da sad mozemo koristit aplikaciju

otvorimo link u browseru
> localhost:3000

prvi put kada otvorimo odredjene linkove   stranicu treba reloadat jer frontend nije dosad ucitavao te linkove

sad registrujemo admina
i nakon registracije koristeci mysql workbench ili beekeeper studio povezemo se na server baze podataka
na linku localhost:3306 koristimo root za korisnika i lozinka za password
kada smo se povezali odaberemo database shemu "gastrozoom"
pronadjemo tabelu user i za registriranog admina promjenimo rucno role korisnika sa "USER" na "ADMIN" i spremimo izmjene u bazi podataka

iduci put kada se prijavimo u aplikaciji kao admin
aplikacija ce nam prikazati i dozvoliti linkove kojim samo admin moze pristupiti

isto tako se moze dodjeliti role "WORKER" gdje ce korisnik imati pristup nesto manje opcija nego admin ali vise od obicnog korisnika
tako da ce moci imati pregled narudzbi i mijenjati status narudzbi

