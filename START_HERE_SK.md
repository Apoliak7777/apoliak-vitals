# Apoliak Vitals — rýchly štart

Aplikácia sa pozrie na tvoj počítač a povie ti, ako je na tom: procesor, pamäť, disky,
programy, dočasné súbory, batéria, grafika, ochrana Windowsu a najväčšie priečinky. Na konci
dostaneš známku od 0 do 100 a zrozumiteľné odporúčania.

**Nič nemení.** Nemaže súbory, nezasahuje do registrov, nevypína služby ani programy po
štarte, nemení nastavenia Windowsu a nepýta si práva správcu. Iba číta. Jediné, čo zapíše,
je správa, ktorú si sám vyexportuješ — a história, ak si ju sám zapneš.

## Spustenie

Dvakrát klikni na:

```text
dist\Apoliak-Vitals.exe
```

V aplikácii stlač **Analyzovať počítač** (v angličtine *Analyze my PC*). To je celé.

Je to **jeden jediný súbor**. Netreba inštalovať Python ani nič iné, nerobí sa žiadna
inštalácia a nezapisuje sa nič do systému. Pokojne si ten súbor skopíruj na plochu, na USB
kľúč alebo na iný počítač — bude fungovať aj tam.

## Čo v aplikácii nájdeš

Vľavo je panel s tlačidlami, hore šesť záložiek:

- **Prehľad** — celková známka, čiastkové skóre za procesor, pamäť, úložisko, údržbu,
  napájanie a **bezpečnosť**, deväť kariet s hodnotami, zoznam strhnutých bodov a odporúčania.
- **Procesy** — programy, ktoré zaberajú najviac pamäte, aj s vyťažením procesora. Len na
  pozretie, nič sa nedá ukončiť.
- **Úložisko** — všetky disky a oddiely, koľko je voľné a či ide o SSD alebo klasický HDD.
  Nižšie pribudli dve nové tabuľky: **Stav diskov** (koľko života disku ešte ostáva) a
  **Najväčšie priečinky**.
- **Zabezpečenie** — novinka. Prehľadne ukáže, či máš zapnutý antivírus a bránu firewall, či
  beží Secure Boot, či Windows čaká na reštart a aké staré sú definície antivírusu.
- **Systém** — Windows, základná doska a BIOS, grafické karty, programy spúšťané pri
  štarte a upozornenia z analýzy.
- **História** — sem sa ukladajú staršie merania, ak si to zapneš. Je tu aj graf **Skóre
  v čase**, teda ako sa známka menila.

Analýza beží na pozadí, takže okno počas nej nezamrzne. Trvá pár sekúnd — najdlhšie
zvyčajne meranie priečinkov.

## Záložka Zabezpečenie — čo znamenajú tie štítky

Pri každom riadku je farebný štítok. Znamená jedno z troch:

- **Zapnuté** — Windows hlási, že to funguje.
- **Vyžaduje pozornosť** — Windows hlási problém, napríklad vypnutú bránu firewall.
- **Neznáme** — aplikácia sa to nedozvedela. To **nie je** to isté ako „vypnuté“. Ak
  Centrum zabezpečenia Windows neodpovie, aplikácia radšej napíše „neznáme“, než by ti
  nepravdivo oznámila, že si bez ochrany. Za neznámy údaj sa nikdy nestrhávajú body.

Jednotlivé riadky:

- **Antivírus** a **Brána firewall** — číta sa priamo z Centra zabezpečenia Windows, takže to
  funguje aj vtedy, keď máš antivírus od iného výrobcu. Názov produktu sa nezobrazuje —
  nedá sa spoľahlivo zistiť bez ďalších technológií a aplikácia si radšej nič nevymyslí.
  Vypnutý antivírus je najťažší nález v celom hodnotení (−30 až −40 bodov), vypnutá brána
  firewall stojí −12 až −18 bodov.
- **Secure Boot** — či je zapnutá bezpečná zavádzacia sekvencia. Ak je vypnutá, aplikácia to
  napíše, ale **body za to nestrhne**. Býva vypnutá aj z úplne legitímnych dôvodov (dvojitý
  operačný systém, staršia doska) a trestať za to by bolo nefér.
- **Čaká sa na reštart** — Windows dokončí niektoré aktualizácie až po reštarte. Ak čaká,
  uvidíš aj dôvod. Stojí to len −3 body, je to skôr pripomienka než chyba.
- **Vek definícií** — ako dávno sa aktualizoval antivírus Windows Defender. Nad 7 dní −8
  bodov, nad 30 dní −14.
- **Posledná kontrola** — dátum poslednej kontroly. Je to len informácia, nemá štítok:
  aplikácia nemá pravidlo o tom, ako často treba kontrolovať, a vymyslieť si ho tu by
  znamenalo napísať na obrazovku názor, ktorý hodnotenie nezastáva.

## Opotrebenie disku a batérie

Toto sú dve nové čísla a obe hovoria o **stave**, nie o zaťažení. Sú v záložke **Úložisko**
v tabuľke **Stav diskov** a na karte **Batéria** v Prehľade (riadok *Kondícia batérie*).

- **Zostávajúci život disku** — moderné SSD si samy počítajú, koľko percenta svojej
  životnosti už minuli. Aplikácia to prečíta a ukáže, koľko ostáva. 98 % znamená takmer nový
  disk. Body sa strhávajú až pod 30 % (−4), pod 20 % (−10) a pod 10 % (−18). Ak disk sám
  hlási kritické varovanie, je to −25 bodov a odporúčanie znie jednoznačne: zálohuj.
- **Stav batérie** — batéria, ktorá bola pri kúpe na 80 Wh a dnes sa nabije na 75 Wh, ukazuje
  „100 % nabitá“, hoci drží menej než kedysi. Aplikácia porovná pôvodnú a dnešnú kapacitu a
  povie ti to. Pod 70 % je to −3 body, pod 60 % −6, pod 50 % −10. Uvidíš aj počet nabíjacích
  cyklov a typ článkov.

**Dôležité:** ak disk alebo batéria toto číslo nehlásia — starší SATA disk, stolný počítač
bez batérie, firmvér, ktorý mlčí — napíše sa `N/A` a **nič sa nestrhne**. Aplikácia nikdy
neodhaduje a nedopočítava. Radšej prizná, že nevie.

## Najväčšie priečinky

V záložke **Úložisko** dole je tabuľka ôsmich priečinkov: Stiahnuté súbory, Plocha,
Dokumenty, Obrázky, Videá, Hudba, dáta aplikácií a dáta aplikácií z Microsoft Store.
Zoradené od najväčšieho.

Prečo to tam je: veta „máš voľných 588 GB“ ti nepovie, čo s tým. Veta „priečinok Videá má
89,8 GB“ áno. Ak je najväčší priečinok nad 20 GB alebo zaberá viac než desatinu disku,
dostaneš k nemu aj odporúčanie.

Aplikácia priečinky iba **premeriava** — zisťuje veľkosť a počet súborov. Nič v nich neotvára,
nečíta ich obsah a nič nemaže. Ak sa do niektorého priečinka nedá pozrieť, napíše sa neznáma
veľkosť, nie nula. Ak sa meranie nestihlo v časovom limite, číslo je označené ako „aspoň
toľko“ — teda spodná hranica, nie konečný súčet.

## Tlačidlo „Otvoriť nastavenie“

Pri niektorých odporúčaniach je tlačidlo **Otvoriť nastavenie** (*Open setting*). Keď naň
klikneš, otvorí sa príslušná stránka Nastavení Windowsu — napríklad Zabezpečenie systému
Windows alebo Úložisko.

**Aplikácia ti tú stránku iba otvorí. Zmenu urobíš ty. Sama aplikácia naďalej nič nemení.**

Otvorenie stránky nie je zmena nastavenia. V programe nie je žiadny kód, ktorý by na tej
stránke niečo prepol, vyplnil alebo potvrdil — tlačidlo je len skratka na miesto, kde to
môžeš urobiť ručne. Pod zoznamom odporúčaní to píše aj samotné okno: *„Otvorí príslušnú
stránku nastavení Windowsu. Nič sa za vás nezmení.“* Po otvorení sa v stavovom riadku objaví
*„Windows otvoril stránku nastavení. Nič sa nezmenilo.“*

Tlačidlo sa spustí **výhradne po tvojom kliknutí** — nikdy počas analýzy — a vie otvoriť len
päť konkrétnych stránok Windowsu. Čokoľvek iné (súbor, program, webová adresa) odmietne.
V konzolovej verzii takéto tlačidlo vôbec nie je.

## Prepnutie do slovenčiny

Slovenčina sa väčšinou nastaví sama podľa Windowsu, takže je možné, že už beží. Ak nie,
v ľavom paneli dole nájdeš **Jazyk** (*Language*), vyber **Slovenčina** a celé okno sa
hneď prepne. To isté platí pre **Vzhľad** (*Theme*) — tmavý alebo svetlý.

Po slovensky hovorí aj konzolová verzia — celá nápoveda (`main.py --lang sk --help`),
tabuľka uložených meraní (`--show-history`) aj priebeh analýzy, ktorý sa vypisuje počas
merania. Preložené je všetko, čo uvidíš, nie len časť.

## Uloženie správy

1. V ľavom paneli si v rozbaľovacom zozname vyber formát: **Text**, **JSON**, **HTML**
   alebo **Markdown**.
2. Stlač **Exportovať správu** (*Export report*) a vyber, kam sa má súbor uložiť.

Ak chceš správu niekomu poslať, dobrá voľba je **HTML** — je to jediný súbor, ktorý sa
otvorí v prehliadači a nič nesťahuje z internetu.

Tlačidlo **Kopírovať do schránky** skopíruje textovú verziu, aby si ju mohol vložiť do
mailu alebo do správy.

## Skrytie osobných údajov pred zdieľaním

V správe je bežne aj cesta k tvojmu profilu, teda tvoje používateľské meno vo Windowse —
napríklad `C:\Users\alexp\AppData\Local\Temp` alebo `C:\Users\alexp\Downloads`.

V ľavom paneli, hneď pod tlačidlami na export, je preto políčko **Skryť osobné údaje**.
Predvolene je vypnuté. Keď ho zaškrtneš, meno tvojho účtu sa vo **všetkých** exportovaných
formátoch aj v kópii do schránky nahradí textom `<user>`.

Pozor, čo to nerobí: neskryje značku a model počítača, verziu BIOS-u, model disku, názvy
programov ani príkazy programov spúšťaných po štarte. Pred odoslaním si správu radšej prejdi
— najmä zoznam programov po štarte.

**Čo sa nezbiera nikdy:** žiadne sériové číslo (ani disku, ani počítača), žiadna IP adresa,
žiadna MAC adresa, žiadny licenčný kľúč ani identifikátor počítača. Model disku a typ
zbernice v správe sú — to je údaj o súčiastke, rovnaký pre všetky kusy toho istého modelu.
Sériové číslo, ktoré by identifikovalo práve tvoj počítač, sa vedome preskakuje.

## História (dobrovoľná)

Predvolene sa neukladá nič. Ak chceš sledovať, ako sa známka mení v čase, choď na záložku
**História** a zaškrtni **Uložiť túto analýzu lokálne**. Od tej chvíle si každá analýza
zapíše len čísla (dátum, známku, vyťaženie, voľné miesto) do súboru:

```text
%LOCALAPPDATA%\Apoliak\Vitals\history.jsonl
```

Žiadne názvy súborov, žiadne cesty, žiadne mená programov, žiadne meno účtu — a ani nové
údaje z verzie 2.1: stav diskov, batérie ani ochrany sa do histórie nezapisujú. Uchováva sa
posledných 200 meraní a súbor môžeš kedykoľvek pokojne vymazať.

Z uložených meraní sa v tej istej záložke kreslí **graf známky v čase**. Kým je políčko
nezaškrtnuté, graf ostáva prázdny, lebo nie je z čoho kresliť — na disk sa nič nezapisuje.

## Konzolová verzia (pre pokročilých)

Konzolová verzia nie je v `.exe` — je určená na skriptovanie a treba na ňu Python.
Uloženie správy bez pýtania:

```powershell
py -3 main.py --output report.html --no-prompt
```

To isté so skrytým menom účtu:

```powershell
py -3 main.py --output report.html --redact --no-prompt
```

Všetky prepínače vypíše `py -3 main.py --help`. Nové merania z verzie 2.1 (bezpečnosť, stav
diskov, najväčšie priečinky) nemajú vlastný prepínač — v konzole sa robia vždy.

## Čomu rozumieť vo výsledku

- Známka začína na 100 a každý nález z nej niečo strhne. Pri každom strhnutí je uvedené
  číslo, z ktorého vychádza, takže si ho vieš overiť.
- **Ku každému strhnutiu bodov dostaneš aj odporúčanie.** Aplikácia ti nikdy nestrhne body
  a potom nenapíše, že je všetko v poriadku — aj mierne nálezy (napríklad pamäť nad 70 %)
  majú vlastnú radu.
- Čo sa nepodarilo zmerať, je uvedené ako `N/A` a **nikdy sa za to nestrhávajú body**. Platí
  to aj pre nové merania: stolný počítač bez batérie ani disk, ktorý svoje opotrebenie
  nehlási, nie sú za to trestané.
- Ak sa meranie priečinka (TEMP alebo niektorého z tvojich) nestihlo dokončiť v časovom
  limite, veľkosť je uvedená ako „aspoň toľko a toľko“. Číslo je spodná hranica, nie konečný
  súčet.
- Ak sa do priečinka vôbec nedá pozrieť (neexistuje alebo naň nemáš práva), veľkosť
  ostane **neznáma** a v upozorneniach nájdeš, o ktorý priečinok išlo. Aplikácia nikdy
  nenapíše „0 bajtov“ len preto, že sa nemala ako pozrieť.
- Vysoké vyťaženie procesora počas aktualizácie, antivírusovej kontroly alebo hry je úplne
  normálne. Toto je momentka, nie diagnóza. Naopak, opotrebenie disku a batérie momentka
  nie je — to je stav, ktorý sa nezmení tým, že zavrieš pár programov.

## Keď zmeníš kód a chceš nové EXE

Dvakrát klikni na `build_exe.bat`. Je to jediný skript v projekte — pripraví si prostredie,
spustí všetkých 957 testov a až potom postaví nový `dist\Apoliak-Vitals.exe`. Ak
niektorý test neprejde, build sa zastaví.

Podrobný technický popis je v `README.md`, presné znenie sľubu o čítaní v `SECURITY.md`.
