# Defense-Dossier
Defense Dossier (synthetic demo) — cryptographically verifiable immutable audit trail: chain of evidence, provenance, RFC 3161 timestamping, Merkle-proofs and reconciliation for construction and regulated finance.
# Defense Dossier (synthetic demo) — cryptographically verifiable immutable audit trail

Chain of evidence, provenance, RFC 3161 timestamping, Merkle-proof & reconciliation for construction & regulated finance.

**Core:** immutable audit trail / chain of evidence / cryptographic integrity / provenance / timestamping / reconciliation.

**Что реально в демо:** хеширование SHA-256, Merkle-дерево, Merkle-proof, логика сверки двух независимых потоков, фильтрация по ролям (Access Control Service) с bypass-resistance через токен.

**Что замокано:** ЭЦП НУЦ РК, RFC 3161 TSA, публичный анкер. Интерфейсы готовы — замена мока на живую интеграцию не требует переписывать ядро.

**Запуск:**

```bash
python3 defense_dossier_demo.py
```

---

## Case Study: Spatial XR AdTech Audit

Применение двухпоточной сверки к XR-рекламе на Android XR-очках:
как доказать рекламодателю, что показ действительно был, —
и доказать площадке, что рекламодатель не накручивает списания, —
без доступа к камерам и персональным данным пользователя.

### Постановка

Единица биллинга — криптографически подтверждённое внимание
(Proof of Attention): показ засчитывается, только если голова пользователя
была направлена на контент достаточно долго (dwell-порог) и относительно
неподвижна. Трекинг глаз не используется — архитектурное решение
(энергопотребление, приватность, дешевле BOM).

### Поток 1 — телеметрия устройства

Смартфон как доверенный edge-валидатор собирает события сессии
(`PresetServed` → `ImpressionValidated` → `GestureInteraction` →
`PresetClosed`), подписывает их ключом устройства (Ed25519) и пакует
в Merkle-дерево сессии. Наружу уходит только Merkle-корень пачки
и inclusion proofs — не сырые данные.

Очки → телефон: поза головы + дискретные жесты + подтверждения.
Сырое видео и суставы руки за пределы очков не выходят.

### Поток 2 — журнал рекламодателя

Журнал списаний рекламодателя: заявленные показы, время, слоты.
Это «заявленная» сторона — ей по построению нельзя доверять вслепую.

### Детектор расхождений

Defense-Dossier сравнивает потоки: заявленные рекламодателем показы
против подтверждённых клиентских `ImpressionValidated` (с валидными
доказательствами внимания). Если расхождение превышает порог политики —
кампания помечается флагом `FRAUD_DISCREPANCY_DETECTED`, биллинг блокируется
до разбора. Порог — настраиваемый параметр, не константа спецификации.

### Почему это работает без камер

Спор «был показ или нет» решается не видеозаписью пользователя,
а цепочкой: on-device доказательство → подпись устройства →
Merkle-анкор → сверка двух независимых потоков. Подделать показ —
значит подделать подпись устройства и Merkle-proof; накрутить списания —
значит разойтись с потоком телеметрии и получить флаг.

### Связка

- Событийный контракт: `schemas/xr-event.schema.json` (v1),
  репозиторий `LIGHTWEIGHT-XR-CONTENT-ENGINE`.
- Доменный профиль биллинга и инвариантов (I3/I4/I6/I7):
  `docs/domain-profiles/xr-adtech-profile.md`,
  репозиторий `decision-intelligence-core`.
