<div align="center">

[![English](https://img.shields.io/badge/EN-English-30363d?style=for-the-badge)](README.md) [![Slovencina](https://img.shields.io/badge/SK-Sloven%C4%8Dina-2ea043?style=for-the-badge)](README.sk.md)

</div>

<div align="center">

# 🩺 Apoliak Vitals

**Analyzátor stavu počítača s Windowsom, ktorý iba číta: prečíta životné funkcie tvojho stroja, premení ich na priehľadné skóre 0–100 a nezmení vôbec nič.**

![Verzia](https://img.shields.io/badge/verzia-2.1.0-1478E0?style=for-the-badge)
![Testy](https://img.shields.io/badge/testy-957%20%C3%BAspe%C5%A1n%C3%BDch-16A916?style=for-the-badge)
![Len na čítanie](https://img.shields.io/badge/re%C5%BEim-len%20na%20%C4%8D%C3%ADtanie-2ea043?style=for-the-badge)
![Bez práv správcu](https://img.shields.io/badge/pr%C3%A1va%20spr%C3%A1vcu-nikdy-E60012?style=for-the-badge)
![Jeden súbor](https://img.shields.io/badge/jeden%20s%C3%BAbor-11%20MB-9B6BE0?style=for-the-badge)

[**Stiahnuť Apoliak-Vitals.exe**](https://github.com/Apoliak7777/apoliak-vitals/releases/latest) · [Slovenský návod](START_HERE_SK.md) · [Bezpečnostné zásady](SECURITY.md)

</div>

---

Apoliak Vitals je nenáročný nástroj na analýzu počítača s Windowsom. Prečíta stav stroja —
edíciu Windowsu a firmvér, procesor, pamäť RAM a stránkovací súbor, disky a ich opotrebenie,
nastavenia ochrany Windowsu, procesy, dočasné súbory, najväčšie používateľské priečinky, dobu
behu, nabitie a opotrebenie batérie, sieťové a grafické adaptéry aj položky po štarte —
premení to na priehľadné skóre zdravia 0–100 a ponúkne jasné, nedeštruktívne rady.

Tento projekt je prvým modulom **Apoliak Optimizer**.

## Čo prináša verzia 2.1

Verzia 2.0 merala **záťaž**: ako veľmi je počítač práve teraz vyťažený. Verzia 2.1
pridáva **stav**: čo je trvalo v neporiadku a čo sa s tým dá robiť.

- **Stav ochrany Windowsu** — antivírus a brána firewall cez API Centra zabezpečenia, Secure
  Boot, čakajúci reštart a to, aké staré sú definície Defenderu. Nová kategória skóre
  **Zabezpečenie** a nová záložka v okne.
- **Opotrebenie disku** zo záznamu NVMe SMART o stave disku: zostávajúca životnosť, teplota,
  hodiny v prevádzke, celkovo zapísané údaje a kritické varovanie, ktoré hlási sám disk.
- **Opotrebenie batérie** z IOCTL batérie: pôvodná kapacita oproti dnešnej kapacite pri plnom
  nabití, počet cyklov a chémia článkov.
- **Najväčšie priečinky** — Stiahnuté súbory, Plocha, Dokumenty, Obrázky, Videá, Hudba,
  lokálne údaje aplikácií a údaje aplikácií z Microsoft Store, merané tým istým obranným
  prechádzačom ako TEMP.
- **Rady, ktoré sa dajú hneď použiť.** Niektoré odporúčania už nesú stránku nastavení
  Windowsu a okno pri nich zobrazí tlačidlo **Otvoriť nastavenie**.
- **Graf histórie** v okne: skóre v čase, nakreslené z dobrovoľnej lokálnej histórie.

Obidve merania opotrebenia fungujú **bez práv správcu** a namiesto hádania hlásia **neznáme**.
Disk SATA, ktorý na dotaz SMART neodpovie, aj tak uvedie svoj model a typ zbernice a všetky
polia o opotrebení nechá prázdne; batéria, ktorej firmvér nezverejňuje kapacitu, nedá o svojej
kondícii vôbec žiadne číslo.

### O tom tlačidle nastavení

**Aplikácia stránku otvorí. Zmenu urobíš ty. Sama aplikácia naďalej nič nemení.**

Otvoriť stránku Nastavení Windowsu neznamená zmeniť nastavenie. V tomto projekte nie je žiadny
kód, ktorý by v Nastaveniach prepol prepínač, vyplnil pole alebo klikol na tlačidlo — tlačidlo
je len skratka na miesto, kde by si zmenu mohol urobiť *ty* sám, ručne.

Je pevne ohradené:

- spustí sa výhradne po vedomom kliknutí, nikdy počas analýzy, hodnotenia ani vykresľovania;
- prijme iba URI `ms-settings:` porovnané s prísnym vzorom; čokoľvek iné — súbor, program,
  webová adresa, iná veľkosť písmen — sa odmietne, neopravuje sa;
- päť stránok, ktoré vôbec kedy vie otvoriť, je `ms-settings:windowsdefender`,
  `ms-settings:windowsupdate`, `ms-settings:storagesense`, `ms-settings:batterysaver` a
  `ms-settings:startupapps`;
- nikdy si nepýta zvýšené oprávnenia;
- konzola nemá nič podobné.

`tests/test_readonly.py` toto ohradenie nepopisuje, ale dokazuje: audit hook sleduje
`analyze_pc` a všetky štyri vykresľovače a tvrdí **nula** otvorení na zápis, **nula** udalostí
`subprocess` alebo `os.startfile`, **nula** socketov a **nula** zápisov do registra; kontrola
cez `ast` navyše tvrdí, že `open_setting` je jediná funkcia v `gui.py`, ktorá sa vie dostať
k `os.startfile`. Podrobnosti sú v [SECURITY.md](SECURITY.md).

## Záruka režimu len na čítanie

Aplikácia stroj pozoruje. Nemaže súbory, nezapisuje do registra, nezastavuje ani nespúšťa
služby, nevypína položky po štarte, nemení schémy napájania, neinštaluje ovládače a nepýta si
práva správcu. Zabalený spustiteľný súbor nesie manifest `asInvoker`, takže Windows nikdy
nezobrazí výzvu na zvýšenie oprávnení.

Jediné súbory, ktoré kedy zapíše, sú:

1. správa, o ktorej export si sám požiadal, a
2. súbor lokálnej histórie — a to až vtedy, keď si históriu sám zapneš.

K registru sa pristupuje cez `winreg` výhradne s `KEY_READ` a každý handle sa zatvára v bloku
`finally`. Každý IOCTL úložiska otvára svoj zväzok alebo zariadenie s `dwDesiredAccess = 0`
(dotazy na metaúdaje, žiadne právo na čítanie ani zápis, žiadne zvýšenie oprávnení). Jedinou
zdokumentovanou výnimkou sú IOCTL batérie: sú to riadiace kódy `FILE_READ_ACCESS`, ktoré handle
s nulovým prístupom odmietnu, a tak `win_battery.py` skúsi najprv nulový prístup a až potom
siahne po `GENERIC_READ` — stále bez zvýšených oprávnení, overené z bežného účtu, a
`GENERIC_WRITE` sa nežiada nikdy.

V zbere, hodnotení ani vykresľovaní nie je žiadne WMI, žiadny COM, žiadny PowerShell, žiadny
`wmic` a žiadny podproces: každý zberač je čistý Python nad `winreg`, `ctypes`, `psutil`, `os`
a `platform`. Jediné volanie, ktoré siaha mimo procesu, je tlačidlo nastavení opísané vyššie, a
to sa stane iba po kliknutí.

Sľub platí doslova, až po štandardnú knižnicu. Priečinok TEMP sa zisťuje z premenných
prostredia `TMP`, `TEMP` a `TMPDIR`, nie cez `tempfile.gettempdir()`. Tá funkcia totiž
použiteľnosť priečinka overuje tak, že v ňom vytvorí, zapíše a zmaže skúšobný súbor — a to je
skutočný zápis, ktorý táto aplikácia nerobí. Známe priečinky sa zisťujú s `KF_FLAG_DEFAULT`,
nikdy s `KF_FLAG_CREATE`, aby aplikácia nevytvorila priečinok, ktorý by jej Windows ochotne
vytvoril.

V celom kóde platia ešte dve pravidlá:

- **Zberač nikdy nevyhodí výnimku.** Zlyhanie platformy alebo oprávnení sa zmení na chýbajúcu
  hodnotu a čitateľné upozornenie. Čiastočné údaje sú lepšie než pád.
- **Meranie sa nikdy nevymýšľa.** Neznáme ostáva neznáme, vykreslí sa ako `N/A` a nestojí ani
  bod. Platí to pre priečinok TEMP, do ktorého sa aplikácia nevie pozrieť, pre disk, ktorý
  odmietne dotaz SMART, aj pre Centrum zabezpečenia, ktoré neodpovie: každý z nich hlási
  neznámu hodnotu, nikdy pohodlnú nulu a nikdy „nie ste chránení“.

## Čo vie verzia 2.1

**Zber**

- Edícia Windowsu, zobrazovaná verzia (napríklad `24H2`), úplná zostava (`26100.9168`) a dátum
  inštalácie, čítané z registra
- Výrobca základnej dosky, model a verzia BIOS; zástupné reťazce od výrobcov, napríklad
  `Default string`, sa nezopakujú, ale ohlásia ako neznáme
- Marketingový názov procesora, počet fyzických a logických jadier, aktuálna a maximálna
  frekvencia
- Vyťaženie procesora celkovo aj po logických jadrách, z jediného merania
- Celková, použitá a dostupná RAM a k tomu stránkovací súbor Windowsu
- Kapacita systémového disku, jeho zaplnenie, súborový systém a typ média SSD/HDD
- Každý pevný oddiel (najviac 12); optické mechaniky a pripojenia, ktoré sa nedajú prečítať,
  sa preskakujú
- **Stav každého fyzického disku** (novinka): model, typ zbernice, typ média, zostávajúca
  životnosť, teplota, hodiny v prevádzke, celkovo zapísané údaje a príznak kritického varovania
  od samotného disku, čítané zo stránky záznamu NVMe SMART / Health Information. Jeden
  fyzický disk odpovie raz, nech nesie koľkokoľvek zväzkov; disk, ktorý nehlási nič, sa vynechá
  a tabuľku nedopĺňa riadok samých `N/A`. **Sériové číslo disku sa zámerne nečíta.**
- Počet bežiacich procesov a najnáročnejšie procesy podľa pamäte, s PID, RSS, podielom na
  pamäti a skutočným percentom procesora — meria sa len pre vypísané procesy, jedinou spoločnou
  pauzou 0.15 s pre celý zoznam, a delí sa počtom logických jadier, aby to sedelo so Správcom
  úloh
- Používateľský TEMP a, ak sa dá prečítať, celosystémový `%SystemRoot%\Temp`, každý
  s veľkosťou, počtom súborov a príznakom „meranie bolo skrátené“. Cesta k TEMP sa zisťuje
  z `TMP`, `TEMP` alebo `TMPDIR`, nikdy cez `tempfile.gettempdir()`, ktorá by zapísala skúšobný
  súbor. Priečinok, ktorý chýba alebo ktorý tento účet nesmie vypísať, hlási **neznámu**
  veľkosť, nie 0 bajtov
- **Najväčšie používateľské priečinky** (novinka): Stiahnuté súbory, Plocha, Dokumenty,
  Obrázky, Videá, Hudba, lokálne údaje aplikácií a údaje aplikácií z Microsoft Store, od
  najväčšieho, každý s veľkosťou, počtom súborov a vlastným príznakom skrátenia. Cesty
  pochádzajú z `SHGetKnownFolderPath`, nie zo skladania `%USERPROFILE%`. Dokumenty a Plocha
  bývajú totiž bežne presmerované do OneDrive a poskladaná cesta by odmerala prázdny zvyšok
  a nahlásila upokojujúce, no nesprávne číslo
- Doba behu a čas posledného štartu
- Percento nabitia batérie, stav nabíjania a zostávajúci čas, k tomu **opotrebenie batérie**
  (novinka): pôvodná kapacita, kapacita pri plnom nabití, počet cyklov a chémia, pričom
  `health_percent` sa odvodzuje z prvých dvoch a je `None` vždy, keď niektorá z nich chýba
- **Stav ochrany Windowsu** (novinka): verdikty o antivíruse a bráne firewall
  z `WscGetSecurityProviderHealth`, vypnuté profily brány firewall, Secure Boot, čakajúci
  reštart a dôvod, prečo sa čaká, posledná kontrola Defenderu a vek definícií
- Počítadlá sieťovej prevádzky a stav linky pre každé rozhranie (najviac 8) — **žiadne IP
  ani MAC adresy**
- Grafické adaptéry (najviac 4) s verziou ovládača, dátumom ovládača a pamäťou adaptéra
- Položky po štarte (najviac 60) zo štyroch kľúčov `Run`/`RunOnce` a z oboch priečinkov Startup

**Analýza**

- Odstupňované skóre zdravia: **50 riadkov pravidiel pre 17 meraní**, až štyri stupne
  závažnosti na jedno meranie namiesto jedinej hranice typu áno/nie
- Čiastkové skóre pre oblasti **Procesor, Pamäť, Úložisko, Údržba, Napájanie a Zabezpečenie**
- Každá zrážka uvádza číslo, z ktorého vychádza, a meranie, ktoré sa nestihlo dokončiť, sa
  cituje ako dolná hranica („aspoň 12.0 GB“, v angličtine „at least 12.0 GB“), nikdy ako
  presný údaj. Spresnenie je preložená veta, nie text natvrdo vpísaný do čísla
- Oblasť, ktorú sa nepodarilo zmerať, sa hlási ako nedostupná, nie ako čistých 100
- Jedna definícia „úplných údajov“, spoločná pre skóre, správu aj rady
- **32 odporúčaní podľa pravidiel**: hranice aj podmienku, ktorá ich spustí, čítajú z toho
  istého miesta ako skóre, takže si rada a skóre nikdy nemôžu protirečiť
- **Ku každej zrážke vždy patrí aj rada** — vrátane miernych stupňov, ktoré pokrývajú
  `medium_cpu`, `medium_ram`, `medium_swap`, `medium_disk`, `medium_disk_full`,
  `some_processes`, `medium_temp` a `medium_uptime`. Žiadna správa nemôže strhnúť body a potom
  napísať „Nezistili sa žiadne naliehavé problémy“
- **Jedenásť odporúčaní nesie stránku nastavení Windowsu** (`action_uri`), z ktorej okno urobí
  tlačidlo **Otvoriť nastavenie**. Tri ju zámerne nemajú: `secure_boot_off` ukazuje na prepínač
  vo firmvéri a `drive_worn` / `drive_failing` opisujú fyzické opotrebenie, ktoré žiadne
  nastavenie nevráti späť. Nesprávna stránka je horšia než žiadna

**Rozhrania a výstup**

- Moderné okno v CustomTkinter so **šiestimi záložkami**, tmavým a svetlým vzhľadom a grafom
  skóre v čase v záložke História
- Plnohodnotné konzolové rozhranie s riadkom priebehu, farbami, tichým režimom a návratovými
  kódmi pre skripty
- Štyri formáty exportu: text, JSON, HTML a Markdown, všetky formulované z toho istého katalógu
- Angličtina a slovenčina všade — správa, každý export, okno, konzolová nápoveda `--help`,
  tabuľka `--show-history` aj kroky priebehu bežiacej analýzy. Rozhranie je dvojjazyčné celé,
  nie dvojjazyčné miestami
- Dobrovoľná lokálna história s porovnaním voči predchádzajúcemu behu
- Skrytie mena účtu vo Windowse: `--redact` v konzole, políčko v okne

## Rýchly štart

**Dvakrát klikni na `dist\Apoliak-Vitals.exe`.** To je celá aplikácia: **jeden súbor**, žiadny
inštalátor, žiadny Python, žiadny priečinok so závislosťami. Skopíruj ho na USB kľúč alebo na
iný počítač a bude fungovať aj tam. Práva správcu nie sú potrebné a ani sa o ne nežiada.
Zostavuje ho `build_exe.bat` (pozri
[Nové zostavenie spustiteľného súboru](#nové-zostavenie-spustiteľného-súboru)).

Windows 10 alebo 11, 64-bitový. Na *spustenie* aplikácie netreba nič iné.

### Spustenie zo zdrojového kódu

Potrebné len vtedy, keď chceš meniť kód. Vyžaduje Python 3.10 alebo novší z
[python.org](https://www.python.org/downloads/windows/) (zapni **Add Python to PATH**) a k tomu
`psutil` a `customtkinter` — jediné dve závislosti projektu. Všetko, čo pribudlo vo verzii 2.1,
je čisté `ctypes`, `winreg` a štandardná knižnica; nepridala sa žiadna nová závislosť.

```powershell
py -3 -m pip install -r requirements.txt
```

Spustenie okna:

```powershell
py -3 gui.py
```

Spustenie konzolovej verzie:

```powershell
py -3 main.py
```

Export správy HTML bez jedinej interaktívnej otázky:

```powershell
py -3 main.py --output report.html --no-prompt
```

## Konzolová referencia

```powershell
.venv\Scripts\python.exe main.py --help
```

Preložená je aj samotná nápoveda: `--lang sk --help` vypíše po slovensky celý výpis parsera —
popis, každý nadpis skupiny, každý prepínač aj pätu s návratovými kódmi. Jazyk sa zisťuje ešte
pred zostavením argparse, takže `--lang` platí aj pre `--help`.

To isté platí pre všetko, čo sa počas behu vypisuje. `analyze_pc` odovzdáva svojmu callbacku
priebehu stabilný kľúč kroku, nie anglickú vetu, a volajúci vykreslí `progress.<key>`
z katalógu, prípadne siahne po `analyzer.PROGRESS_LABELS[key]`. Krokov je trinásť: `system`,
`cpu`, `ram`, `disk`, `partitions`, `drive_health`, `processes`, `top_processes`, `temp`,
`folders`, `security`, `extras` a `done`. Pod `--lang sk` znie riadok priebehu
`[ 35%] Načítavam využitie pamäte`, nie `[ 35%] Reading memory usage`; okno číta tie isté kľúče.

Zberače z verzie 2.1 **nemajú vlastné konzolové prepínače**: zabezpečenie, stav diskov aj
meranie priečinkov sú pri konzolovom behu vždy zapnuté, presne tak, ako ich predvolene nastavuje
`analyze_pc`. Zoznam prepínačov nižšie je oproti verzii 2.0 nezmenený a presne zodpovedá
`main.py --help`.

### Prepínače analýzy

| Prepínač | Predvolené | Účinok |
|---|---|---|
| `--cpu-sample-seconds SECONDS` | `1` | Dĺžka merania procesora, 0 až 5 sekúnd. Mimo tohto rozsahu sa beh zastaví s návratovým kódom 2. Jediný prechod `percpu` poslúži celkovému číslu aj zoznamu po jadrách, takže sa čas merania minie len raz. |
| `--top N` | `5` | Koľko najnáročnejších procesov sa načíta. `0` zoznam vypne a spolu s ním preskočí aj meranie procesora. Akákoľvek iná hodnota pridá jednu spoločnú pauzu 0.15 s. |
| `--no-temp-scan` | vypnuté | Úplne preskočí meranie priečinka TEMP. Veľkosť TEMP potom uvádza `N/A` a nestojí žiadne body. |
| `--temp-scan-seconds SECONDS` | `12` | Časový limit pre priečinky TEMP, rozdelený rovnomerne medzi tie, ktoré sa budú merať. Sken, ktorému sa limit minie, sa hlási ako skrátený, nikdy ako menšie číslo. |
| `--no-startup` | vypnuté | Preskočí zber položiek po štarte. |
| `--no-gpu` | vypnuté | Preskočí zber údajov o grafických adaptéroch. |

### Prepínače výstupu

| Prepínač | Predvolené | Účinok |
|---|---|---|
| `--format {text,json,html,markdown}` | `text`, alebo odvodené z cesty exportu | Formát výstupu. |
| `--export [PATH]` | vypnuté | Vyexportuje výsledok. Bez cesty vznikne v aktuálnom priečinku automaticky pomenovaný súbor `apoliak_vitals_report_YYYYMMDD_HHMMSS.<ext>`; ak je názov obsadený, pridá sa `_2`, `_3`, … namiesto prepísania. |
| `--output PATH` | žiadne | Výslovné umiestnenie. Zapína `--export` a má pred ním prednosť. Súbor, ktorý pomenuješ, sa zapíše presne tam — pomenovať súbor znamená prepísať ho. Prijme sa aj priečinok a dostane vygenerovaný názov bez kolízie. |
| `--no-prompt` | vypnuté | Nepýtať sa na nič interaktívne. |
| `--redact` | vypnuté | Skryje meno účtu vo Windowse všade vo výstupe vrátane ciest. |
| `--lang {en,sk}` | zistené | Jazyk správy, hlásení a `--help`. Poradie zisťovania: `APOLIAK_LANG`, potom miestne nastavenia systému, potom angličtina. |
| `--color {auto,always,never}` | `auto` | Farby v termináli. Escape sekvencie sa do exportovaného súboru nikdy nedostanú. V režime `auto` sa rešpektujú `NO_COLOR` a `FORCE_COLOR`. |
| `--quiet` | vypnuté | Vypíše iba riadok so skóre. Spolu s ním zmizne indikátor priebehu aj stavové hlásenia („Správa uložená do …“); vyžiadaný export sa aj tak vykoná. |
| `--fail-under N` | žiadne | Skončí s kódom 3, keď je skóre nižšie ako N (0–100). |
| `--version` | — | Vypíše verziu a skončí. |

### Prepínače histórie (dobrovoľná)

| Prepínač | Predvolené | Účinok |
|---|---|---|
| `--save-history` | vypnuté | Pridá tento beh do lokálneho súboru histórie. Bez neho sa nezapíše nič. |
| `--history-path PATH` | `%LOCALAPPDATA%\Apoliak\Vitals\history.jsonl` | Použije iný súbor histórie. |
| `--show-history [N]` | vypnuté, `10` bez hodnoty | Vypíše posledných N uložených behov a skončí. `0` vypíše všetky. Hlavička tabuľky sa riadi `--lang`. Táto cesta kódu sa nedotkne žiadneho systémového API. |
| `--compare` | vypnuté | Zobrazí zmenu oproti predchádzajúcemu uloženému behu. Číta sa skôr, než sa uloží tento beh, takže „predchádzajúci“ nikdy nemôže byť ten istý. |

### Návratové kódy

| Kód | Význam |
|---:|---|
| 0 | Úspech |
| 1 | Chyba pri behu (analýza, hodnotenie, vykresľovanie, export alebo chýbajúci `psutil`) |
| 2 | Neplatné argumenty |
| 3 | Skóre pod `--fail-under` |

Návratový kód 1 pokrýva aj chybu vykresľovača alebo exportéra: konzola vypíše na stderr
obyčajný riadok „Analýza sa bezpečne ukončila s chybou: …“ namiesto výpisu zásobníka. Tá istá
tabuľka sa vypisuje na konci `--help`, vo zvolenom jazyku.

Príklady:

```powershell
# strojovo čitateľný výstup na stdout, stavové riadky sa naň nedostanú
.venv\Scripts\python.exe main.py --format json --no-prompt > snapshot.json

# jediný riadok, vhodné na naplánovanú kontrolu
.venv\Scripts\python.exe main.py --quiet --no-prompt --fail-under 60

# HTML na zdieľanie so skrytým menom účtu
.venv\Scripts\python.exe main.py --output report.html --redact --no-prompt

# uloží tento beh a vypíše, ako sa skóre pohlo od minula
.venv\Scripts\python.exe main.py --save-history --compare --no-prompt
```

## Grafické rozhranie

Okno má bočný panel (analýza, formát exportu, export, kopírovanie do schránky, **Skryť osobné
údaje**, jazyk, vzhľad) a **šesť záložiek**. Analýza beží na pracovnom vlákne typu daemon
a hlási sa späť cez front; widgetov sa dotýka výhradne hlavné vlákno Tk, takže okno nezamrzne
a priebežne ukazuje riadok priebehu — s pomenovaním každého kroku, v jazyku zvolenom v bočnom
paneli. Nič v rozhraní nevie zmeniť stroj: záložka s procesmi zámerne nemá tlačidlo na
ukončenie úlohy a záložka Zabezpečenie hlási stav ochrany bez toho, aby ponúkala jeho zmenu.

**Skryť osobné údaje** je v okne obdobou `--redact`. Predvolene je vypnuté a je umiestnené pri
ovládacích prvkoch exportu, lebo práve tam na ňom záleží: momentka na obrazovke z počítača
nikdy neodíde, vyexportovaná alebo skopírovaná správa áno. Keď je zaškrtnuté, každý formát
exportu *aj* kópia do schránky nesú `<user>` namiesto mena účtu. Ak by niektorý exportér bol
príliš starý na to, aby skrytie rešpektoval, export sa radšej odmietne, než by správa odišla
neskrytá.

| Záložka | Obsah |
|---|---|
| **Prehľad** | Skóre zdravia s ukazovateľom priebehu, **šesť** čiastkových skóre oblastí, deväť kariet s hodnotami (Systém, Procesor, Pamäť, Systémový disk, Aktivita, Dočasné súbory, Batéria, Sieť, Grafika), zrážky zo skóre a odporúčania. |
| **Procesy** | Najnáročnejšie procesy zoradené podľa využitia pamäte — názov, PID, pamäť, podiel na pamäti a percento procesora. Zoznam je len na čítanie. |
| **Úložisko** | Tri karty: každý pevný disk a oddiel s kapacitou, obsadeným a voľným miestom, zaplnením, súborovým systémom a typom SSD/HDD; **stav diskov** (model, zbernica, zostávajúca životnosť, teplota, hodiny v prevádzke, zapísané údaje, kritické varovanie); a **najväčšie priečinky** s veľkosťou, počtom súborov a cestou. |
| **Zabezpečenie** | Novinka vo verzii 2.1. Antivírus, brána firewall, Secure Boot, čakajúci reštart, vek definícií a posledná kontrola, každé so štítkom zapnuté / vyžaduje pozornosť / neznáme, k tomu bezpečnostné zrážky a bezpečnostné rady. Keď Centrum zabezpečenia neodpovedalo, záložka to napíše — „neznáme, nie vypnuté“. Sľub o režime len na čítanie sa opakuje práve tu, kde oň čitateľ najskôr zapochybuje. |
| **Systém** | Operačný systém, firmvér, grafické adaptéry, položky po štarte a upozornenia z tohto behu. |
| **História** | Dobrovoľné políčko, cesta k súboru histórie, **graf skóre v čase** nakreslený na plátno z uložených behov a samotné behy od najnovšieho. Kým je políčko nezaškrtnuté, na disk sa nezapisuje nič. |

Každé odporúčanie, ktoré nesie stránku nastavení Windowsu, dostane vo svojom riadku tlačidlo
**Otvoriť nastavenie**, a to v Prehľade aj v Zabezpečení. Text pod zoznamom vymedzuje
hranicu: *„Otvorí príslušnú stránku nastavení Windowsu. Nič sa za vás nezmení.“* Po úspešnom
otvorení sa objaví *„Windows otvoril stránku nastavení. Nič sa nezmenilo.“*

Jazyk a vzhľad sa prepínajú naživo z bočného panela; celé okno sa prekreslí na mieste a graf sa
po každej zmene veľkosti prekreslí na skutočnú šírku plátna.

## Formáty exportu

| Formát | Prípona | Poznámky |
|---|---|---|
| `text` | `.txt` | Ten istý vykresľovač, aký používa konzola, len bez farieb. UTF-8. |
| `json` | `.json` | Úplná verzovaná momentka (`schema_version` `2.1`), odsadená, `ensure_ascii=False`. Stabilné rozloženie kľúčov, takže starý export sa dá prečítať aj v neskoršej verzii. Vety zrážok a odporúčaní sa získavajú cez ten istý katalóg ako v ostatných troch formátoch. Nesie zoznam `export_errors` — pri zdravom exporte prázdny. |
| `html` | `.html` | Jediný samostatný dokument: vložené CSS, žiadne písma, žiadne obrázky, žiadne skripty, žiadne externé požiadavky. Dá sa bezpečne poslať mailom. |
| `markdown` | `.md` | Tabuľky a sekcie, na vloženie do ticketu alebo na wiki. |

Formát sa berie z `--format`, inak sa odvodí z prípony exportovaného súboru (`.txt`, `.text`,
`.json`, `.html`, `.htm`, `.md`, `.markdown`), inak je to `text`. Neznámy názov formátu je
jediná vec, pre ktorú vykresľovač vyhodí výnimku — konkrétne `ValueError`.

Naprieč všetkými štyrmi platia dva sľuby:

- **Jedno znenie.** `src/i18n.py` je jediným zdrojom vykresleného textu. Vykresľovač zavolaný
  bez jazyka siahne po angličtine z katalógu, nie po vete, ktorú si náhodou poskladal ten, kto
  hodnotu vyrobil. JSON, text, HTML a Markdown z jedného behu tak opisujú nález vždy tými
  istými slovami a tými istými číslami.
- **Vykresľovač nikdy nezhodí beh.** Všetky štyri dokumenty — vrátane JSON — sa skladajú
  sekciu po sekcii, každá za vlastnou poistkou; jedno poškodené meranie pripraví o obsah len
  tú jednu sekciu, ktorú nahradí jednoriadkové ospravedlnenie, nie celý export. V JSON sa taká
  sekcia zapíše ako `null` a pomenuje sa v `export_errors`, aby čitateľ rozoznal „toto nikto
  nezmeral“ od „toto sa nedalo zapísať“; každá vetva sa navyše ešte pred vrátením overí ako
  serializovateľná, takže nepriateľský *typ* padne do tej istej siete ako nepriateľská hodnota.
  Ak by aj tak zlyhalo celé vykreslenie, konzola to ohlási ako neúspešný beh s návratovým
  kódom 1.

### Čo sa zmenilo v tvare JSON

`schema_version` je teraz `"2.1"`. Nič sa neodstránilo ani nepremenovalo — existujúci čitateľ
funguje ďalej — a pribudli tri kľúče najvyššej úrovne, v tomto poradí v dokumente:

```text
schema_version, generated_by, analyzed_at, system, cpu, ram, disk, partitions,
drive_health, processes, temp, folder_usage, uptime_seconds, battery, network,
gpus, startup_items, security, health, recommendations, warnings, export_errors
```

- **`drive_health`** — zoznam, jedna položka za každý fyzický disk, ktorý odpovedal:
  `drive, model, bus_type, media_type, percentage_used, life_left_percent,
  temperature_celsius, power_on_hours, data_written_bytes, critical_warning, source`.
  `life_left_percent` je odvodené `100 − percentage_used`, vypísané naplno, aby čitateľ nemusel
  poznať vzorec. Prázdny zoznam znamená, že sa nepodarilo prečítať nič. **Žiadne sériové číslo.**
- **`folder_usage`** — zoznam, od najväčšieho: `key, label, path, size_bytes, file_count,
  truncated`. `size_bytes: null` znamená, že priečinok sa nepodarilo zmerať, čo nie je to isté
  ako `0`.
- **`security`** — objekt: `antivirus, antivirus_name, firewall, secure_boot,
  reboot_pending, defender_last_scan, signature_age_days, details`. Tri polia s verdiktom nesú
  `"good"`, `"weak"`, `"bad"` alebo `"unknown"`. `details` je zoznam dvojíc `{key, value}` —
  zatiaľ `firewall_profiles_off`, `reboot_sources` a `security_center`. `antivirus_name` je vždy
  `null`: názov produktu si vyžaduje COM/WMI, ktoré tento projekt nepoužíva, a hádať ho by
  znamenalo vymýšľať si.

Dva existujúce objekty dostali nové polia; všetky sú voliteľné a keď sú neznáme, majú
hodnotu `null`:

- **`battery`** dostal `design_capacity_mwh`, `full_charge_capacity_mwh`, `cycle_count`,
  `chemistry` a odvodené `health_percent`.
- každá položka **`recommendations`** dostala `action_uri` — stránku `ms-settings:`, o ktorej
  rada hovorí, alebo `null`. Je to údaj na prezretie; žiadny exportér ho sám neotvára.

## Skóre zdravia

Skóre začína na 100 a body môže stratiť výhradne na pravidle z tabuľky nižšie. Všetkých **50
riadkov** je verejným vyhlásením „toto meranie za touto hranicou stojí toľkoto bodov“ a každá
zrážka vypísaná v správe cituje číslo, z ktorého vychádza.

Nosné sú tri vlastnosti:

- **Neznáme meranie nikdy nestojí body.** Jeho pravidlo ostane nevyhodnotené a jeho oblasť sa
  hlási ako nedostupná, takže žiadne rozhranie nevystaví čisté vysvedčenie, ktoré si počítač
  nezaslúžil.
- **Z jedného pravidla môže zabrať iba jeden stupeň** — ten najhorší prekročený. Stupne sú
  alternatívy, nikdy sa nesčítavajú.
- **Šesť hraníc z verzie 1.0 ostáva ako kotvy.** Procesor nad 70 % (15 bodov), RAM nad 80 %
  (20), voľné miesto pod 20 GB (20), viac než 180 procesov (10), TEMP nad 3 GB (10) a doba behu
  nad 48 hodín (5) sú presne to, čo zverejnila verzia 1.0, a sú stupňom `standard` svojho
  pravidla. Verzia 2.0 každú kotvu obklopila miernejšími a prísnejšími stupňami a verzia 2.1
  vedľa nich pridala nové pravidlá bez toho, aby sa jedinej dotkla.

| Meranie | Podmienka | Stupeň | Body | Závažnosť |
|---|---|---|---:|---|
| Vyťaženie procesora | nad 55 % | mild | 6 | info |
| | nad 70 % | standard | 15 | warning |
| | nad 85 % | high | 22 | warning |
| | nad 95 % | severe | 28 | critical |
| Vyťaženie pamäte RAM | nad 70 % | mild | 8 | info |
| | nad 80 % | standard | 20 | warning |
| | nad 90 % | high | 28 | critical |
| | nad 95 % | severe | 34 | critical |
| Zaplnenie stránkovacieho súboru | nad 50 % | mild | 4 | info |
| | nad 75 % | standard | 10 | warning |
| | nad 90 % | severe | 16 | critical |
| Voľné miesto na systémovom disku | pod 50.0 GB | mild | 8 | info |
| | pod 20.0 GB | standard | 20 | warning |
| | pod 10.0 GB | high | 26 | critical |
| | pod 5.0 GB | severe | 32 | critical |
| Zaplnenie systémového disku | nad 85 % | mild | 5 | info |
| | nad 92 % | standard | 12 | warning |
| | nad 97 % | severe | 18 | critical |
| Bežiace procesy | nad 150 | mild | 4 | info |
| | nad 180 | standard | 10 | warning |
| | nad 250 | high | 14 | warning |
| | nad 350 | severe | 18 | warning |
| Veľkosť priečinka TEMP | nad 1.0 GB | mild | 4 | info |
| | nad 3.0 GB | standard | 10 | warning |
| | nad 10.0 GB | high | 14 | warning |
| | nad 25.0 GB | severe | 18 | warning |
| Doba behu systému | nad 1 deň | mild | 2 | info |
| | nad 2 dni | standard | 5 | warning |
| | nad 7 dní | high | 8 | warning |
| | nad 14 dní | severe | 10 | warning |
| Položky po štarte | nad 12 | mild | 3 | info |
| | nad 20 | standard | 6 | warning |
| | nad 30 | severe | 10 | warning |
| Nabitie pri behu na batérii | pod 25 % | mild | 2 | info |
| | pod 15 % | standard | 4 | warning |
| | pod 7 % | severe | 6 | critical |
| **Ochrana antivírusom** | ohrozená alebo horšie | standard | 30 | critical |
| | vypnutá | severe | 40 | critical |
| **Ochrana bránou firewall** | ohrozená alebo horšie | standard | 12 | warning |
| | vypnutá | severe | 18 | warning |
| **Vek definícií antivírusu** | nad 7 dní | standard | 8 | warning |
| | nad 30 dní | severe | 14 | warning |
| **Čakajúci reštart Windowsu** | čaká sa | standard | 3 | info |
| **Vlastné hodnotenie disku** | hlási zlyhávanie | standard | 25 | critical |
| **Zostávajúca životnosť disku** | pod 30 % | mild | 4 | info |
| | pod 20 % | standard | 10 | warning |
| | pod 10 % | severe | 18 | critical |
| **Zostávajúca kapacita batérie** | pod 70 % | mild | 3 | info |
| | pod 60 % | standard | 6 | warning |
| | pod 50 % | severe | 10 | warning |

Stupeň a závažnosť sú v tabuľke uvedené pod kódovými názvami, ktoré nesie samotné pravidlo:
`mild` mierny, `standard` štandardný, `high` vysoký, `severe` vážny; `info` informácia,
`warning` upozornenie, `critical` kritické.

Veľkosti sú binárne: `20.0 GB` znamená 20 GiB, teda číslo, ktoré ukazuje Windows.

Verdikty o ochrane stoja na stupnici — `good` = 0, `weak` = 1, `bad` = 2 — a dve bezpečnostné
hranice (0.5 a 1.5) znamenajú „ohrozená alebo horšie“ a „vypnutá“. `unknown` na tej stupnici
vôbec nie je, takže nikdy nemôže spustiť pravidlo.

Tabuľka vzniká z jediného zdroja a dá sa kedykoľvek vypísať:

```powershell
.venv\Scripts\python.exe -c "from src.health_score import score_rules
for r in score_rules(): print(r.key, r.tier, r.points, r.condition)"
```

### Secure Boot zámerne nestojí nič

Secure Boot sa zbiera aj vypisuje, a keď je vypnutý, dostane jeden riadok rady. Zámerne
preň **nie je žiadny riadok so zrážkou**. Býva vypnutý z mnohých legitímnych dôvodov, medzi
nimi dvojitý štart systémov a starší firmvér, a strhávať zaň body by bolo nečestné. Rada to
takto aj hovorí.

### Poistky skóre

- **Voľné miesto a percento zaplnenia sa neúčtujú dvakrát.** Opisujú ten istý disk z dvoch
  strán, takže keď zaberie pravidlo o voľných bajtoch, pravidlo o percentách sa zahodí.
  Percentuálne pravidlo tak pokrýva iba to, čo bajtové minie: veľký disk, ktorý je takmer plný,
  no stále má viac než 20 GB voľných.
- **Stránkovací súbor menší než 1 GiB sa nehodnotí vôbec.** Stránkovací súbor s veľkosťou
  256 MB je aj na úplne zdravom počítači zaplnený na 95 %, takže jeho percento nehovorí nič.
- **Nabitie batérie je nálezom iba vtedy, keď sa počítač naozaj vybíja.** Notebook
  v zásuvke na 20 % sa nabíja, nie je v problémoch.
- **Za opotrebenie diskov sa strháva raz za momentku, nie raz za disk.** Počítač s dvoma
  opotrebovanými diskami má jeden problém, ktorý treba riešiť, a účtovať zaň dvakrát by
  znamenalo, že skóre závisí od toho, koľko diskov je v počítači. `most_worn_drive()` vyberie
  ten najhorší a rada si importuje ten istý výber, takže obe menujú ten istý disk.
- **„Žiadny disk nám to nepovedal“ nie je „každý disk je v poriadku“.** Metrika vlastného
  hodnotenia disku ostáva neznáma, kým na otázku naozaj neodpovie aspoň jeden disk, takže
  Úložisko sa hlási ako zmerané iba vtedy, keď sa naozaj niečo zmeralo.

### Žiadna zrážka bez rady

`src/recommendations.py` číta svoje hranice priamo zo `SCORE_RULES` a pokrýva každý stupeň,
ktorý stojí body, aj tie mierne. Tento invariant je absolútny:

- **žiadny kľúč zrážky nikdy nevznikne bez odporúčania, ktoré pokrýva tú istú podmienku** —
  hodnota RAM 72 % stojí 8 bodov *a* zároveň vypíše `medium_ram`, a každé nové pravidlo
  z verzie 2.1 (`antivirus_off`, `firewall_off`, `stale_signatures`, `reboot_pending`,
  `drive_worn`, `drive_failing`, `battery_worn`) má tiež vlastný kľúč odporúčania;
- **`all_good` vzniká vždy len osamote.** Nemôže sa objaviť vedľa zrážky, lebo pribúda len
  vtedy, keď sa nenašlo nič iné;
- mierne stupne pokrývajú `medium_cpu` (nad 55 %), `medium_ram` (nad 70 %), `medium_swap`
  (nad 50 %), `medium_disk` (pod 50 GB voľných), `medium_disk_full` (nad 85 %),
  `some_processes` (nad 150), `medium_temp` (nad 1 GB) a `medium_uptime` (nad 1 deň), všetky
  so závažnosťou `info`;
- rada k disku sa riadi tým istým potláčacím pravidlom ako skóre, takže beh, ktorý strháva za
  voľné bajty, nikdy neodpovie vetou o percente zaplnenia, a naopak.

Dve odporúčania zámerne existujú bez toho, aby za nimi stála akákoľvek zrážka:
`secure_boot_off` (vysvetlené vyššie) a `large_folder`, ktoré zaberie, keď je najväčší zmeraný
priečinok nad 20 GiB **alebo** nad 10 % disku, na ktorom leží. Potrebné sú obe — 20 GB je veľa
na 256 GB notebooku a nič zvláštne na 4 TB stolnom počítači. Priečinok TEMP je z tohto výberu
vylúčený, lebo už má vlastný nález a hlásiť jedno meranie ako dva problémy by bolo dvojité
počítanie.

Citovanie v odporúčaniach sa riadi rovnakým pravidlom čestnosti ako zrážky: keď bol sken
skrátený, aj `large_temp`, `medium_temp` a `large_folder` uvádzajú veľkosť ako dolnú hranicu.
Jeden beh nikdy nepovie to isté meranie dvoma spôsobmi.

### Keď sú údaje neúplné

`data_complete` má práve jednu definíciu, v `health_score.required_values_present()`. Je
pravdivé vtedy, keď sa podarilo zmerať všetkých šesť hodnôt — vyťaženie procesora, vyťaženie
RAM, voľné miesto na disku, počet procesov, veľkosť TEMP a dobu behu — **a sken TEMP nebol
skrátený**. Všetko, čo hovorí o úplnosti, číta ten jeden predikát: riadok „Úplné údaje“ v každej
správe a v každom exporte, `HealthAssessment.data_complete` aj odporúčanie `incomplete_data` —
ktoré zaberie, keď beh vytvoril upozornenia *alebo* keď predikát neplatí.

Zberače z verzie 2.1 do tohto predikátu zámerne **nevstupujú**. Stolný počítač nemá batériu,
disk SATA nezverejňuje číslo o opotrebení a prísne zabezpečený počítač nemusí odpovedať Centru
zabezpečenia — nič z toho nie je neúplná *analýza* a označiť kvôli tomu momentku za neúplnú by
ten príznak zbavilo významu.

Na nepravdu ho vedia zhodiť dve veci okolo priečinka TEMP.

**Sken, ktorému sa minul časový limit,** nie je meranie:

- momentka nesie `temp_truncated = true` a každý export to vynesie na povrch — správy označia
  veľkosť ako „čiastočný sken“ a pridajú jeden vysvetľujúci riadok, JSON nastaví
  `temp.truncated`;
- skóre pravidlo `large_temp` aj tak uplatní, ak už čiastočná veľkosť prekročila hranicu.
  Čiastočná veľkosť môže byť iba menšia, takže zabrať na nej nikdy nie je falošný poplach
  a zrážka je nanajvýš príliš mierna;
- ale zrážka, jej rada aj jej parametre znejú ako dolná hranica — „Priečinok TEMP obsahuje veľa
  údajov (aspoň 12.0 GB).“ — nikdy ako presný súčet, ktorý aplikácia nedopočítala. Spresnenie
  sa ukladá ako jazykovo neutrálny parameter `bound` a formuluje ho až vykresľovač, takže
  slovenská správa znie „(aspoň 12.0 GB)“ a žiadny formát si nemusí vymýšľať vlastné znenie;
- a `data_complete` prejde na nepravdu, takže čitateľ sa dozvie, že momentka je dolná hranica,
  nie celý obraz.

**Priečinok TEMP, do ktorého sa nedá pozrieť,** tiež nie je meranie. Ak cesta chýba, nie je
priečinkom alebo ju tento účet nesmie vypísať, hlási sa s `size_bytes = null` — neznáme, nie
nula — a pribudne upozornenie, ktoré priečinok pomenuje. Nestojí to žiadne body
a `data_complete` prejde na nepravdu. Záleží na tom preto, že `TMP` sa z prostredia berie tak,
ako je: pokazené `TMP` sa kedysi hodnotilo ako dokonale čistý priečinok TEMP, čo bolo jediné
miesto, kde si aplikácia meranie vymyslela.

### Ako dlho beh trvá

Obidva skeny priečinkov zdieľajú jeden časový rozpočet, `analyzer.TOTAL_SCAN_SECONDS` =
8 sekúnd. TEMP ide prvý a zvyčajne skončí dávno pred koncom svojej polovice; čo z nej zvýši,
dostane sken najväčších priečinkov, ktorý má zaručenú aspoň jednu sekundu, nech TEMP urobil
čokoľvek. Pridanie merania priečinkov vo verzii 2.1 preto nemôže zdvojnásobiť dĺžku behu.

Konzola prepisuje polovicu určenú pre TEMP prepínačom `--temp-scan-seconds` (predvolene 12 s),
takže beh z príkazového riadka môže stráviť na TEMP viac času než okno; sken priečinkov aj tak
dostane zvyšok 8-sekundového rozpočtu, najmenej však jednu sekundu. Všetko ostatné v analýze
stojí asi sekundu a pol plus dĺžku merania procesora.

### Pásma skóre

| Skóre | Stav |
|---:|---|
| 90–100 | Výborný |
| 75–89 | Dobrý |
| 50–74 | Potrebuje optimalizáciu |
| 0–49 | Slabý |

Toto skóre je momentka, nie benchmark a nie diagnóza. Vysoké vyťaženie procesora je počas hry,
aktualizácie alebo renderovania úplne normálne. Keď sa nejakú metriku nepodarilo prečítať,
správa napíše, že údaje boli neúplné, namiesto toho, aby predstierala, že meranie vyšlo.

## Jazyky

Rozhranie, správa, každý export, konzolová nápoveda `--help`, tabuľka `--show-history` aj kroky
priebehu sa dodávajú v **angličtine** a **slovenčine** (s plnou diakritikou), po **418 kľúčoch**
v každej, s rovnakými zástupnými symbolmi pri každom kľúči. Jazyk sa vyberá v tomto poradí:

1. prepínač `--lang` alebo bočný panel okna;
2. premenná prostredia `APOLIAK_LANG`;
3. miestne nastavenia operačného systému;
4. angličtina.

```powershell
$env:APOLIAK_LANG = "sk"
.venv\Scripts\python.exe main.py
```

Katalóg je jediným zdrojom vykresleného znenia. Vykresľovač, ktorý dostal požiadavku bez
jazyka, nevypisuje vlastnú anglickú vetu; načíta angličtinu z katalógu, takže dva formáty
jedného behu nemôžu ten istý nález sformulovať rozdielne. Pri chýbajúcom kľúči sa použije
anglická predvolená hodnota volajúceho, namiesto toho, aby sa správa pokazila, a zástupný symbol,
ku ktorému nikto nevedel dodať hodnotu, zmizne aj so svojou zátvorkou, namiesto toho, aby sa
vypísalo `(N/A)`.

Počítané slovné spojenia skloňuje jazyk, nie vykresľovač. Slovenčina potrebuje tri tvary tam,
kde angličtine stačia dva — 1 `bod`, 2 až 4 `body`, 0 a od 5 vyššie `bodov` — takže správa
vypíše „− 3 body“ a „− 5 bodov“, nie nesprávne „− 3 bodov“.

Spresnenia sa prekladajú z toho istého dôvodu. Kód, ktorý vedel pod číslo položiť len dolnú
hranicu, pripojí parameter `bound` namiesto toho, aby do hodnoty vpísal „aspoň“, a spoločný
vykresľovač ho rozloží cez `report.at_least` — takže anglická správa povie „at least 12.0 GB“
a slovenská „aspoň 12.0 GB“ z jednej a tej istej momentky.

Každý dodaný kľúč má miesto, kde sa volá. Reťazec v katalógu je sľubom, že ho produkt niekde
ukazuje; kľúče, ktoré také miesto stratili, sa odstránili, aby nevyzerali ako funkcia, ktorá
už neexistuje.

## Lokálna história (dobrovoľná)

História je predvolene vypnutá. Kým v konzole nepridáš `--save-history` alebo v okne v záložke
História nezaškrtneš **Uložiť túto analýzu lokálne**, nezapíše sa nič.

- Umiestnenie: `%LOCALAPPDATA%\Apoliak\Vitals\history.jsonl`
  (na systémoch bez `%LOCALAPPDATA%` tá istá cesta v domovskom priečinku)
- Formát: JSON Lines, jeden malý objekt na jeden beh, najnovší na konci
- Uchovávanie: najnovších 200 behov; staršie záznamy sa pri ďalšom pridaní zahodia
- Obsah: deväť polí — časová značka, skóre, stav, percento procesora, percento RAM, voľné bajty
  na disku, bajty v TEMP, počet procesov a doba behu. **Žiadne cesty, žiadne názvy procesov,
  žiadny názov počítača, žiadne sériové čísla, žiadne meno účtu.** Zberače z verzie 2.1 do
  súboru nepridávajú nič: opotrebenie diskov, opotrebenie batérie, veľkosti priečinkov ani stav
  ochrany sa neukladajú
- Poradie: `--show-history` vypisuje od najstaršieho; záložka História v okne uvádza od
  najnovšieho a z tých istých behov kreslí graf skóre v čase

Súbor sa prepisuje cez susedný dočasný súbor a atomické nahradenie, takže prerušený beh ho
nemôže zničiť, a riadky, ktoré sa nedajú rozobrať, sa preskočia, namiesto toho, aby zhodili
celé načítanie. Vymazať ten súbor je vždy bezpečné.

```powershell
.venv\Scripts\python.exe main.py --save-history --no-prompt   # uloží tento beh
.venv\Scripts\python.exe main.py --show-history 20            # vypíše posledných 20 behov
.venv\Scripts\python.exe main.py --compare --no-prompt        # zmena od posledného behu
```

## Súkromie

Analyzátor nikam nič neposiela. Žiadna telemetria, žiadna kontrola aktualizácií a žiadne sieťové
volanie akéhokoľvek druhu — export do HTML je samostatný práve preto, aby ani otvorenie správy
nikam nesiahalo. Sieťový zber číta len počítadlá prevádzky a stav linky: **nikdy sa nezbiera
žiadna IP adresa ani MAC adresa**, v žiadnom formáte, so skrytím ani bez neho.

**Nikde sa nezbiera žiadne sériové číslo, MAC adresa, IP adresa ani identifikátor stroja.**
Popisovač úložného zariadenia sériové číslo nesie a `win_storage.py` toto pole zámerne
preskakuje; `psutil.net_if_addrs` sa nevolá nikdy; v projekte nie je žiadne vyhľadanie
licenčného kľúča, GUID stroja ani hardvérového odtlačku. *Model* disku a typ zbernice sa
zbierajú a opisujú súčiastku, ktorá je rovnaká v každom kuse toho istého modelu — sériové číslo,
ktoré by identifikovalo práve tento počítač, je tá časť, ktorá sa preskakuje.

Vyexportovaná správa aj tak môže obsahovať identifikujúce podrobnosti: cesty k TEMP a k tvojim
používateľským priečinkom (obsahujú meno účtu vo Windowse), názvy procesov, názvy položiek po
štarte, názvy sieťových rozhraní, výrobcu stroja, model a verziu BIOS, model disku a stav
ochrany tohto počítača. **Export do JSON navyše nesie úplné príkazové riadky položiek po
štarte**, ktoré zvyčajne obsahujú cesty k nainštalovaným aplikáciám; textová, HTML a Markdown
správa uvádzajú položky po štarte len názvom a zdrojom.

Skrytie osobných údajov zamaskuje meno účtu — aj segment `C:\Users\<meno>`, kdekoľvek sa
objaví, aj každý ďalší výskyt toho mena — v celej správe, v odporúčaniach, v upozorneniach,
v príkazoch po štarte, v cestách k priečinkom aj vo vypísaných cieľových cestách. Je dostupné
v oboch rozhraniach:

- konzola: `--redact`;
- okno: políčko **Skryť osobné údaje** v bočnom paneli, predvolene vypnuté, uplatní sa na každý
  formát exportu aj na kópiu do schránky.

Maskuje meno účtu; stroj neanonymizuje. Model, verzia BIOS, model disku, príkazové riadky po
štarte a názvy procesov skrytie prežijú. Pred zdieľaním si správu prejdi. Podrobnosti sú
v [SECURITY.md](SECURITY.md).

## Testy

Sada používa iba spúšťač zo štandardnej knižnice Pythonu. **957 testov** v sedemnástich
moduloch. Dva testy sa samy preskočia, keď účet nesmie vytvárať symbolické odkazy — čo je na
Windowse mimo režimu pre vývojárov predvolený stav:

```powershell
.venv\Scripts\python.exe -m unittest discover -s tests -v
```

| Modul | Testy |
|---|---:|
| `test_analyzer.py` | 141 |
| `test_exporters.py` | 111 |
| `test_health_score.py` | 100 |
| `test_cli.py` | 71 |
| `test_recommendations.py` | 70 |
| `test_i18n.py` | 62 |
| `test_win_storage.py` | 59 |
| `test_win_security.py` | 59 |
| `test_folder_usage.py` | 55 |
| `test_report.py` | 47 |
| `test_gui.py` | 38 |
| `test_win_battery.py` | 37 |
| `test_utils.py` | 34 |
| `test_history.py` | 29 |
| `test_models.py` | 27 |
| `test_readonly.py` | 12 |
| `test_version.py` | 5 |

Zberače prijímajú voliteľný argument `psutil_module` alebo vkladateľný čítač a vykresľovače
voliteľný prekladač, takže testy podstrkujú atrapy namiesto toho, aby sa dotýkali skutočného
stroja. Moduly Win32 skrývajú volania systému za malými švami — `_load_kernel32`,
`_open_device`, `_device_io_control`, `_load_api`, `_load_shell_api`, `provider_health` —
takže test nahradí operačný systém ako celok, zatiaľ čo každý dekodér bufferov je čistá funkcia
`bytes → hodnota`, ktorá nepotrebuje žiadny hardvér. Pri každom novom zberači sa navyše tvrdí,
že s `platform.system()` prepísaným na `"Linux"` vráti bezpečnú prázdnu hodnotu.

`test_gui.py` preveruje čisté pomocné funkcie okna bez toho, aby ho otvoril, takže sada
nepotrebuje displej. `test_readonly.py` je sada s audit hookom opísaná
v [SECURITY.md](SECURITY.md#4-the-proof-the-audit-hook-test); spúšťa samostatný podproces
s interpreterom, takže cena za stále zapnutý audit hook sa zaplatí raz a odíde s tým procesom.

## Nové zostavenie spustiteľného súboru

Dvakrát klikni na `build_exe.bat`. Je to jediný skript v projekte: vytvorí súkromné `.venv`,
nainštaluje závislosti potrebné na zostavenie, spustí celú testovaciu sadu a až potom spustí
samotné zostavenie. Neúspešný test zostavenie zastaví.

Výstupom je **jediný súbor** `dist\Apoliak-Vitals.exe` (~11 MB), ktorý nesie ikonu, zdroj
s verziou a `app.manifest` — manifest si pýta `asInvoker`, takže aplikácia nikdy nežiada
o zvýšenie oprávnení. Kompresia UPX je zámerne vypnutá, lebo komprimované binárky
z PyInstalleru sú známym spúšťačom falošných poplachov v antivírusových heuristikách.

Zostavovať sa musí na Windowse: PyInstaller zostavuje pre platformu, na ktorej beží.

## Štruktúra projektu

```text
Apoliak-Vitals/
├── src/
│   ├── __init__.py          # lenivé zisťovanie podmodulov, aby jedna vrstva nevliekla druhú
│   ├── analyzer.py          # zber len na čítanie, analyze_pc, PROGRESS_LABELS
│   ├── win_registry.py      # čítanie registra s KEY_READ: edícia, firmvér, GPU, po štarte
│   ├── win_security.py      # Centrum zabezpečenia + KEY_READ: antivírus, firewall, Secure Boot
│   ├── win_storage.py       # IOCTL len na dotazy: model disku, zbernica, opotrebenie NVMe SMART
│   ├── win_battery.py       # IOCTL batérie: pôvodná kapacita oproti plnému nabitiu, cykly
│   ├── folder_usage.py      # SHGetKnownFolderPath + spoločný prechádzač: najväčšie priečinky
│   ├── processes.py         # poradie procesov len na čítanie, pamäť a procesor
│   ├── models.py            # zmrazené typované modely momentky, SCHEMA_VERSION = "2.1"
│   ├── health_score.py      # odstupňovaná tabuľka skóre, čiastkové skóre, „úplné údaje“
│   ├── recommendations.py   # bezpečné rady, hranice a stránky nastavení
│   ├── i18n.py              # anglické a slovenské reťazce vrátane tvarov množného čísla
│   ├── report.py            # vykresľovač čistého textu a spoločné riešenie bound/label
│   ├── exporters.py         # text / JSON / HTML / Markdown
│   ├── history.py           # dobrovoľná lokálna história vo formáte JSON Lines
│   └── utils.py             # formátovanie, skrytie údajov a obranný prechádzač priečinkov
├── tests/                   # 957 jednotkových testov v sedemnástich moduloch a atrapy v helpers.py
├── docs/
│   ├── architecture.md      # mapa modulov, vlákna, správanie pri zlyhaní
│   └── roadmap.md           # čo je hotové a čo príde ďalej
├── dist/
│   └── Apoliak-Vitals.exe   # zostavená aplikácia: jeden súbor, nič iné netreba
├── main.py                  # vstupný bod konzoly
├── gui.py                   # vstupný bod grafického rozhrania
├── build_exe.bat            # jediný skript: venv, závislosti, testy, zostavenie do jedného súboru
├── Apoliak_Vitals.spec      # špecifikácia PyInstalleru pre ten jeden spustiteľný súbor
├── app.ico                  # ikona aplikácie, zobrazuje sa aj v okne a na paneli úloh
├── app.manifest             # asInvoker, DPI aware, long-path aware
├── version_info.txt         # zdroj s verziou súboru pre Windows
├── requirements.txt         # psutil, customtkinter
├── requirements-build.txt   # to isté plus PyInstaller
├── pyproject.toml           # metadáta balenia a konfigurácia nástroja ruff
├── CHANGELOG.md
├── SECURITY.md              # sľub o režime len na čítanie do detailu
├── START_HERE_SK.md         # krátky slovenský návod pre netechnických používateľov
├── PROJECT_PLAN.md          # pôvodné zadanie
└── LICENSE
```

## Filozofia

> Každý zásah je vysvetlený. Každá zmena sa dá vrátiť.

Verzia 2.1 stále iba analyzuje a odporúča. Jediné, čo vie spôsobiť mimo seba, je otvorenie
stránky Nastavení Windowsu po kliknutí na tlačidlo — čo ukáže, kde nastavenie býva, a nič
nezmení. Skutočná zmena nastavenia nie je otázkou jedného refaktoru: je to nový modul za
vlastnou hranicou, s potvrdením, s ukážkou presnej zmeny, s cestou späť a s vlastnými testami.
Pravidlá pre to sú zapísané v `docs/roadmap.md` a v `SECURITY.md`.

## Licencia

MIT — pozri [LICENSE](LICENSE).
