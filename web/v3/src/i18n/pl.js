/* Polski. Nazwy middleware pozostaja nieprzetlumaczone — to identyfikatory
   w kodzie. */

export default {
  nav: {
    items: [
      ['Architektura', '#how'],
      ['Mechanizmy', '#controls'],
      ['Wdrożenie', '#deployment'],
      ['Zgodność', '#compliance'],
      ['Dla inwestorów', '#investors'],
      ['Status', '#status'],
    ],
    cta: 'Pilotaż w trybie lustrzanym',
    skip: 'Przejdź do treści',
  },

  hero: {
    title: 'Bezpieczeństwo API działające w Państwa sieci, nie w naszej.',
    sub: 'AEGIS mapuje każdy endpoint na podstawie rzeczywistego ruchu, zatrzymuje ataki, których firewall sygnaturowy nie widzi, i wytwarza dowody wymagane przez NIS2 oraz DORA. Jeden plik binarny w języku Go, na Państwa sprzęcie i Państwa bazie danych. Żaden ruch nie opuszcza Państwa infrastruktury.',
    cta: 'Zacznij od pilotażu lustrzanego',
    link: 'Jak to działa, od początku do końca',
    note: 'Pilotaż nie umieszcza nas na ścieżce żądań. Państwa proxy wysyła kopię; my nigdy nie dotykamy odpowiedzi. Można zatrzymać bramę w środku pilotażu — ruch tego nie zauważy.',
  },

  terminal: {
    title: 'Zapis każdego żądania, a nie kwartalny skan.',
    sub: 'AEGIS czyta ruch produkcyjny na bieżąco — z kopii lustrzanej podczas pilotażu, inline gdy zdecydują się Państwo na egzekwowanie. Każda blokada, redakcja i nowo zauważony endpoint trafiają do dziennika śledczego w momencie zdarzenia, pieczętowanego co godzinę — dzięki temu dziennik potrafi wykazać, że nie był później edytowany.',
    link: 'Zobacz, jak decyduje łańcuch',
  },

  controls: {
    title: 'Sześć mechanizmów, jeden uporządkowany łańcuch.',
    tiles: [
      ['Firewall aplikacyjny', 'OWASP CRS v4 + filtr XXE'],
      ['Maskowanie danych', 'Karty, numery ID, adresy e-mail'],
      ['Podpisana tożsamość', 'JWT zweryfikowany, przekazany z podpisem'],
      ['BOLA / BFLA', 'Dostęp do cudzych obiektów, REST i GraphQL'],
      ['Pasywne odkrywanie', 'Katalog endpointów na żywo'],
      ['Izolacja najemców', 'Cache i baza w osobnych przestrzeniach'],
    ],
  },

  architecture: {
    title: 'Kolejność jest nośna.',
    sub: 'Tożsamość ustala się zanim uruchomi się cokolwiek innego. Sfałszowane nagłówki są usuwane, zanim którykolwiek mechanizm mógłby im zaufać. Firewall działa przed odkrywaniem, więc zablokowany atak nigdy nie trafia do katalogu. Dwadzieścia trzy middleware w ośmiu etapach, w tej kolejności, zanim żądanie dotrze do Państwa backendu.',
    head: ['Nr', 'Etap', 'Middleware', 'Kroków'],
    stages: ['Ustalenie', 'Odcisk palca', 'Utwardzenie', 'Filtrowanie', 'Inspekcja', 'Odkrywanie', 'Autoryzacja', 'Wykrywanie i redakcja'],
    note: 'Kolejność nie jest dokumentacją. Jest przypięta testem, który opisuje konsekwencję złamania każdej reguły — proza się rozjeżdża, test nie. Ta strona twierdziła, że łańcuch ma osiem kroków, dopóki ktoś ich nie policzył.',
  },

  deployment: {
    title: 'Self-hosting nie jest opcją wdrożenia. Jest produktem.',
    sub: 'Salt, Noname, Imperva i Akamai dostarczają bezpieczeństwo API jako SaaS: potrzebują kopii Państwa ruchu we własnej chmurze. Dla banku podlegającego DORA, dla szpitala czy podmiotu publicznego to nie jest kwestia preferencji — to próg, którego nie są w stanie przekroczyć. AEGIS to jeden plik binarny. Bez agentów, bez sidecarów, bez konta u kogoś innego, bez ruchu opuszczającego sieć. Rezydencja danych jest domyślna, a nie dodatkiem w wersji enterprise.',
    modes: [
      ['Lustro', 'Zero ryzyka. Tak zaczyna się pilotaż.', 'Państwa proxy wysyła kopię każdego żądania. AEGIS nigdy nie stoi na ścieżce żądania i nigdy nie dotyka odpowiedzi. Można zatrzymać bramę w środku pilotażu i nic się dla użytkowników nie zmieni — to zastrzeżenie, które kończy większość pierwszych rozmów, usunięte zamiast odpierane.'],
      ['Obserwacja', 'Inline, ale bez blokowania.', 'Pełny łańcuch działa na prawdziwym ruchu: każdy endpoint skatalogowany, każde ustalenie zgłoszone, każda odpowiedź sklasyfikowana — i nic nie odrzucone, nic nie zredagowane. Krok między czytaniem raportu a zaufaniem decyzji o blokadzie.'],
      ['Egzekwowanie', 'Cały łańcuch podejmuje decyzje.', 'WAF, limity żądań, kontrola IP i botów, blokowanie BOLA i BFLA, redakcja odpowiedzi. Każdy mechanizm ma udokumentowany wybór fail-open albo fail-closed, więc awaria Redisa jest decyzją podjętą przez Państwa z wyprzedzeniem, a nie przez bramę za Państwa.'],
    ],
    note: 'Wszystkie trzy to ten sam plik binarny i ten sam plik konfiguracyjny. Przejście od lustra do egzekwowania jest ustawieniem, nie migracją.',
  },

  compliance: {
    title: 'Ten sam sygnał, który chroni API, zasila dokumentację.',
    sub: 'Każde ustalenie łączy się z kontrolą, którą sprawdza europejski audyt, poprzez OWASP API Top 10. Podpisany raport to Ed25519 na kluczu trzymanym osobno od wszystkich innych sekretów, a Państwa audytor sprawdza go na własnej maszynie narzędziem reportverify — samodzielnym plikiem binarnym, który odmawia działania z kluczem wziętym z weryfikowanego dokumentu. Weryfikacja nie kosztuje go zaufania ani do Państwa, ani do nas.',
    frameworks: [
      ['NIS2', 'Dyrektywa w sprawie bezpieczeństwa sieci i informacji, art. 21 i 23', 'Odkryte endpointy, brakujące uwierzytelnianie i ujawnienia danych odpowiadają obowiązkom zarządzania ryzykiem. Skorelowane incydenty niosą terminy z art. 23 — wczesne ostrzeżenie w 24 godziny i zgłoszenie w 72 godziny — a zamknięcie incydentu nie usuwa terminu, który został przekroczony.'],
      ['DORA', 'Rozporządzenie o operacyjnej odporności cyfrowej, art. 8–10 i 17–19', 'Artykuły o zarządzaniu ryzykiem ICT odpowiadają odkrywaniu i ocenie postawy; artykuły o incydentach odpowiadają rejestrowi, który oddziela to, co brama zaobserwowała, od tego, co operator oświadczył. Pisane dla podmiotów finansowych w UE, gdzie warstwa bezpieczeństwa SaaS trzymająca kopię ruchu jest trudniejszym pytaniem.'],
      ['ISO 27001', 'Zarządzanie bezpieczeństwem informacji, Załącznik A', 'Odkrywanie, ocena postawy i ścieżka działań administratora odpowiadają kontrolom Załącznika A dotyczącym dostępu, logowania i bezpiecznej eksploatacji.'],
    ],
    limitsTitle: 'Czego podpis nie dowodzi',
    limits1: 'Dziennik śledczy jest pieczętowany co godzinę korzeniami Merkle w podpisanym łańcuchu; rejestr incydentów i ścieżka działań administratora są łańcuchowane i podpisywane tak samo. Usunięcie wiersza, edycja albo obcięcie końca są wykrywalne — także wtedy, gdy robi to operator.',
    limits2: 'Właściwe słowo to wykrywalność ingerencji, nigdy odporność na nią. Klucz podpisujący trzyma strona poddawana audytowi, więc podpis dowodzi, że dokument nie został zmieniony po wytworzeniu — a nie, że powstał z kompletnych danych. Zewnętrzna kotwica, urząd znacznika czasu albo dziennik przejrzystości, zamknęłaby tę lukę; nie jest zbudowana. Każdy podpisany dokument mówi o tym wewnątrz siebie, a system odmawia podpisania takiego, który nie zawiera sekcji ograniczeń.',
    limitsLink: 'Jak zbudowane są łańcuchy',
  },

  investors: {
    title: 'Dlaczego to i dlaczego teraz.',
    sub: 'Każda liczba na tej stronie ma źródło, które możemy pokazać. Nie ma tu szacowania wielkości rynku: nie mierzyliśmy go, a liczba, której nie zmierzyliśmy, byłaby pierwszą rzeczą, którą Państwo sprawdzą.',
    blocks: [
      [
        'Terminy już minęły',
        'NIS2 musiała zostać wdrożona do prawa krajowego w całej UE do 17 października 2024. DORA obowiązuje podmioty finansowe w UE od 17 stycznia 2025. To są obowiązki z datami, a nie intencje — i dlatego kupujący w tej kategorii umówi spotkanie w tym roku, a nie w przyszłym.',
      ],
      [
        'Miejsce działania jest całą przewagą',
        'Każda funkcja, którą tu widać, istnieje gdzieś na rynku, zwykle dojrzalsza. Tym, czego zasiedziały gracz nie skopiuje, jest model wdrożenia: firma SaaS zbudowana na własnej chmurze nie sprzeda pliku binarnego działającego w centrum danych klienta, bo ten plik konkuruje z jej własną marżą. Technicznie nic ich nie powstrzymuje. Powstrzymuje ich własny model biznesowy.',
      ],
      [
        'Co jest zbudowane i skąd to wiemy',
        '27 700 linii kodu produkcyjnego w Go wobec 28 200 linii testów — więcej kodu testowego niż produkcyjnego. Progi pokrycia testami od 70% do 100% dla każdego pakietu, egzekwowane w CI. Jedenaście niezmienników bezpieczeństwa zapisanych jako skrypty; każdy z nich to błąd, który raz trafił do produktu i już nie trafi. Testowanie mutacyjne jako praktyka, nie hasło: kod jest celowo psuty, żeby sprawdzić, czy testy to zauważą — i to wykryło jedenaście testów, które były zielone na zepsutym kodzie. Wszystkie jedenaście wymienione z osobna, dlatego liczba nie jest okrągła.',
      ],
      [
        'Czego nie ma — powiedziane jako pierwsze',
        'Brak klienta. Brak przychodu. Brak niezależnego testu penetracyjnego — dokument zakresu jest napisany, zlecenie nie zostało złożone. Brak SOC 2 i brak certyfikatu ISO, bo to proces i audytor, a nie funkcja produktu. Jeden inżynier po stronie technicznej. Gotowość technologiczna na poziomie TRL 5, można argumentować za 6: system działa i jest zweryfikowany od końca do końca we własnym środowisku, a do TRL 7 brakuje jednego wdrożenia na cudzym rzeczywistym ruchu. To jeden pilotaż, nie rok pracy.',
      ],
    ],
    note: 'Dłuższa wersja jest pod spodem: opis architektury i artykuły inżynierskie. Nic w nich nie przeczy kodowi — test w CI przerywa budowanie, gdy dokument i kod się nie zgadzają, i tak właśnie znaleziono dwa błędy wymienione na tej stronie.',
    link: 'Przeczytaj opis architektury',
  },

  status: {
    title: 'Wcześnie — i mówimy to wprost.',
    sub: 'Działająca brama z prawdziwymi mechanizmami i większą ilością kodu testowego niż produkcyjnego. Czym jeszcze nie jest, mówi tutaj, zamiast pozwolić Państwu dowiedzieć się później — to drugie kosztuje więcej.',
    shipped: 'Gotowe',
    open: 'Otwarte',
    done: [
      ['Pełny łańcuch mechanizmów', 'Dwadzieścia trzy middleware: WAF, DLP, podpisana tożsamość JWT, BOLA i BFLA, pasywne odkrywanie, izolacja najemców.'],
      ['Profile per konsument', 'Wolumen, odmówione autoryzacje, brakujące ścieżki i rozrzut endpointów — każde ustalenie nazywa wymiar i wielkość odchylenia.'],
      ['Obsługa GraphQL', 'BOLA, odkrywanie i wykrywanie PII obejmują operacje GraphQL, nie tylko ścieżki REST.'],
      ['Egzekwowanie schematu', 'Odrzuca nieudokumentowane pola ciała wobec Państwa kontraktu OpenAPI — zamyka mass assignment.'],
      ['Dowody z wykrywalną ingerencją', 'Godzinne pieczęcie Merkle na dzienniku śledczym, podpisane głowy rejestru incydentów i ścieżki działań administratora.'],
      ['Bezpieczne zachowanie przy awarii', 'Każdy mechanizm ma udokumentowany wybór fail-open albo fail-closed, a wartość domyślna jest zapisana wraz z uzasadnieniem.'],
    ],
    todo: [
      ['Brak płacących klientów', 'Żaden pilotaż nie działał jeszcze na cudzym ruchu. Bylibyście Państwo pierwsi — i dokładnie dlatego pilotaż zaczyna się w trybie lustrzanym.'],
      ['Brak zewnętrznego pentestu', 'Dokument zakresu jest napisany; zlecenie nie zostało złożone. Istnieje wewnętrzna praca adwersaryjna i dyscyplina, która ją znalazła.'],
      ['Brak zewnętrznej kotwicy', 'Podpisane dowody żyją w Państwa bazie, a klucz należy do Państwa — operator, który go trzyma, mógłby nadpisać zapis i podpisać go ponownie. Urząd znacznika czasu to zamyka; nie jest zbudowany.'],
      ['Brak certyfikacji', 'Brak SOC 2, brak certyfikatu ISO. To proces i audytor, a nie funkcja — dziś możemy przekazać dowód techniczny, który do takiego procesu wchodzi.'],
    ],
    link: 'Przeczytaj nasze teksty inżynierskie',
  },

  pilot: {
    title: 'Uruchomcie AEGIS na kopii swojego ruchu przez tydzień.',
    sub: 'Państwa proxy wysyła nam kopię każdego żądania. Nie jesteśmy na ścieżce, nigdy nie dotykamy odpowiedzi, a zatrzymanie bramy w trakcie pilotażu nic nie zmienia dla użytkowników. Na koniec otrzymują Państwo raport: ukryte API, endpointy wycierające dane i informację, kto je wywołuje.',
    bullets: [
      'Tydzień, tryb lustrzany, bez opłat',
      'Nic na ścieżce żądań, nic do wycofania',
      'Ustalenia odniesione do NIS2, DORA i ISO 27001',
      'Działa na Państwa sprzęcie — ruch nie opuszcza sieci',
    ],
    form: {
      name: 'Imię i nazwisko',
      email: 'Służbowy e-mail',
      company: 'Firma',
      interest: 'Interesuje mnie',
      select: 'Wybierz...',
      options: ['Pilotaż', 'Demo dla przedsiębiorstwa', 'Inwestycja lub partnerstwo'],
      message: 'Co powinniśmy wiedzieć?',
      optional: 'opcjonalnie',
      submit: 'Zacznij pilotaż lustrzany',
      sending: 'Wysyłanie...',
      thanks: 'Dziękujemy, odezwiemy się w ciągu doby.',
      mail: 'Otwieranie klienta poczty...',
    },
  },

  footer: {
    blurb: 'Brama bezpieczeństwa API we własnej infrastrukturze, napisana w Go. Państwa sprzęt, Państwa baza danych, żaden ruch nie opuszcza sieci. Szukamy partnerów wdrożeniowych.',
  },

  englishOnly: ' (po angielsku)',
}
