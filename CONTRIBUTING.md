# CONTRIBUTING

Opis pracy w zespole

## Workflow
- Pracujemy przez Pull Requesty.

Zasady:
- `main` jest główną i chronioną gałęzią projektu
- Nie wrzucamy zmian bezpośrednio do `main`
- Do każdej zmiany tworzymy osobny branch
- Po zakończeniu pracy tworzymy Pull Request do `main`
- Inne osoby z zespołu sprawdzają zmianę przed mergem
- Po akceptacji robimy merge do `main`


## Nazwy branchy

Branch powinien krótko opisywać co jest robione np:

- docs/readme
- docs/threat-model
- feat/cli-init
- feat/crypto-core
- fix/header-parser
- test/adversarial-tests
- ci/github-actions


## Commity
używamy prefiksów takich jak: 

`feat` - nowa funkcja
`fix` - poprawa błędu
`docs` - dokumentacja
`test` - testy
`ci` - konfiguracja CI
`chore` zmiany organizacyjne

przykładowo:
- `docs: aktualizacja README`
- `feat: dodanie komendy init`
- `fix: poprawa walidacji nagłówka`
- `test: dodanie testów integracyjnych`
- `ci: dodanie GitHub Actions`


## Pull Request
Każdy Pull Request powinien mieć:

- krótki opis zmian
- informację, co zostało sprawdzone
- przypisanie autora
- review od innej osoby z zespołu


## Review
- Standardowo wymagamy minimum 1 akceptacji
- Zmiany dotyczące kryptografii, formatu pliku albo bezpieczeństwa powinny mieć 2 reviewerów
- Autor powinien sam przeczytać swoje zmiany przed wysłaniem PR
- Komentarze z review rozwiązujemy przed mergem


## Merge

Po zaakceptowaniu Pull Requesta robimy merge do `main`

Preferowany sposób: squash & merge.
