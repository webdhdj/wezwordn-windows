# CRYPTOGRAPHY — توثيق التشفير في WezWordn

> نطاق هذه الوثيقة: ما هو منفّذ فعليًا في الشيفرة الموجودة في هذا المستودع وقت الكتابة — وحدات `WezWordnCore/Sources/*` الثماني وملف `AppIntegration/KeychainKeyProvider.swift`. كل ادعاء أدناه قابل للتتبع إلى ملف مصدر مذكور بجانبه. ما ليس في الشيفرة ليس في هذه الوثيقة إلا في قسم «الحدود الصريحة» (§8) بوصفه **غير منفّذ**. نموذج التهديد والحدود الأمنية العامة في `SECURITY.md`، وبنية الفصل بين المناطق في `ARCHITECTURE.md` §3.

---

## 1) مبادئ ملزمة

1. **لا تشفير منزلي (no home-grown crypto):** كل البدائيات التشفيرية في وحدات WezWordn تأتي من حزمة `apple/swift-crypto` (الوحدة `Crypto`) — انظر `WezWordnCore/Package.swift`: التبعية الخارجية الوحيدة للحزمة كلها. الاستثناء الوحيد المكتوب يدويًا هو تركيب `PBKDF2` نفسه فوق `HMAC` الجاهز من الحزمة نفسها (§5.1)، لأن `swift-crypto` لا توفّر `PBKDF2` أصلًا — وهذا موثّق في رأس `LocalDataVault/PBKDF2.swift`.
2. **تشفير خزنة Bitwarden الأصلية لا يُنفّذ هنا إطلاقًا:** يبقى داخل `BitwardenSdk` (نواة Rust عبر `BitwardenFFI`) دون أي مساس من كود WezWordn (§7).
3. **فصل المفاتيح:** مفتاح تخزين الملفات المحلي، ومفاتيح حزم الطوارئ/المشاركة، ومفتاح النسخ الاحتياطي المشتق من كلمة مرور، وبيانات اعتماد حساب Bitwarden — أربعة نطاقات مستقلة؛ لا مفتاح يُشتق من آخر ولا يُعاد استخدامه عبر نطاقين.
4. **فشل التحقق = رفض كامل:** أي فشل في `AES-GCM tag` أو بصمة أو إصدار تنسيق يوقف العملية، ويُحذف أي ناتج جزئي كُتب أثناء فك تشفير ملف (§2).

## 2) جدول الخوارزميات — كل ما يُستخدم فعليًا

| البدائية | الاستخدام | الوحدة / الملف المصدر | ملاحظات دقيقة من الكود |
|---|---|---|---|
| `AES-256-GCM` (`AES.GCM.seal/open`، مفتاح 32 bytes، ‏`nonce` ‏12 bytes، ‏`tag` ‏16 bytes) | تشفير الملفات المُجزّأ، حزم الطوارئ، حزم المشاركة، ختم النسخ الاحتياطي | `LocalEncryptedStorage`، `EmergencyRecovery`، `SecureSharing`، `LocalDataVault/VaultBackup.swift` | حجم المفتاح يُتحقق منه صراحة (`== 32`) في `LocalEncryptedStorage`، ويُرفض غيره بـ `invalidKeySize` |
| `Curve25519 Key Agreement (X25519)` (`Curve25519.KeyAgreement`) | تبادل مفاتيح لكل حزمة: زوج `ephemeral` جديد × مفتاح المستلم العام | `EmergencyRecovery`، `SecureSharing` | لا مفاتيح ثابتة للتشفير نفسه؛ المفتاح المتماثل يُشتق لكل حزمة (§3) |
| `HKDF-SHA256` (`SharedSecret.hkdfDerivedSymmetricKey(using: SHA256.self, … outputByteCount: 32)`) | اشتقاق مفتاح الحزمة من السر المشترك | `EmergencyRecovery`، `SecureSharing` | `salt` ‏32 bytes لكل حزمة؛ `sharedInfo` مختلف لكل وحدة (§3) — فصل نطاق (domain separation) |
| `HMAC-SHA1 / HMAC-SHA256 / HMAC-SHA512` (`HMAC<…>.authenticationCode`) | قلب `HOTP/TOTP` | `LocalTOTP/LocalTOTP.swift` (`OTPGenerator.hotp`) | `SHA1` هنا عبر `Insecure.SHA1` من `swift-crypto` — تسمية الحزمة تعكس ضعف SHA-1 كمقاومة تصادم، بينما استخدامها داخل `HMAC` هو ما تفرضه متجهات RFC (§4) |
| `HMAC-SHA256` كـ `PRF` | قلب `PBKDF2` | `LocalDataVault/PBKDF2.swift` | انظر §5.1 |
| `PBKDF2-HMAC-SHA256` (RFC 8018 §5.2) | اشتقاق مفتاح النسخ الاحتياطي من كلمة مرور المستخدم | `LocalDataVault/VaultBackup.swift` | افتراضيًا `210_000` تكرار؛ `salt` ‏16 bytes لكل تصدير (§5.2) |
| `SHA-256` (`SHA256.hash` / `SHA256()`) | بصمات سلامة فقط — ليست تشفيرًا | `SecureSharing` (بصمة الحزمة)، `VaultBackup` (بصمة الـ store والـ blobs)، `LocalDataVault` (بصمة النص الصريح عند التخزين) | التفاصيل في §3.2 و§5.2 و§5.3 |
| `SHA-1` (`Insecure.SHA1.hash`) | حساب هاش HIBP محليًا فقط | `HIBPClient/HIBPClient.swift` (`sha1Hex(of:)`) | تفرضه واجهة HIBP نفسها؛ لا يُستخدم لأي غرض آخر (§6) |
| `Base32` (RFC 4648) | ترميز/فك أسرار OTP | `LocalTOTP/LocalTOTP.swift` (`Base32`) | تنفيذ محلي موثّق في الكود: يقبل غياب `=` padding، يتجاهل المسافات، غير حسّاس لحالة الأحرف |
| `PBKDF2-SHA256` / `Argon2id` | `KDF` حساب Bitwarden الأصلي | **`BitwardenSdk` فقط** — لا يوجد أي تنفيذ لهما في `WezWordnCore` | انظر §7 — بما فيه ما **لا** يمكن التحقق منه من هذا المستودع |

وحدتان بلا أي تشفير أصلًا (حسب `Package.swift` لا تعتمدان على منتج `Crypto`): ‏`ExtendedLoginFields` (نماذج `Codable` وتحقق وترحيل فقط — التشفير عند الحفظ مسؤولية طبقة التخزين)، و`VaultHealth` (تحليل نقيّ على بيانات مفكوكة في الذاكرة؛ تقدير الـ entropy فيها — `length × log2(poolSize)` — حساب heuristic موثّق في الكود وليس بدائية تشفيرية).

## 3) حزم المفتاح العام — `EmergencyRecovery` و`SecureSharing`

المخطط واحد في الوحدتين، منفّذ **بشكل مستقل في كل منهما** (لا كود مشترك بينهما — نص الكود في `SecureSharing.swift` يصرّح بذلك)، ومفصول النطاق بقيمة `info` مختلفة:

```
ephemeral = Curve25519.KeyAgreement.PrivateKey()        // جديد لكل حزمة
shared    = ephemeral.sharedSecretFromKeyAgreement(with: recipientPublicKey)
key       = HKDF-SHA256(shared, salt = random 32 bytes,
                        info = <per-module, أدناه>, output = 32 bytes)
nonce     = random 12 bytes
sealed    = AES-256-GCM.seal(plaintext, using: key, nonce: nonce)
package.ciphertext = sealed.ciphertext ‖ sealed.tag      // tag آخر 16 bytes
```

| البند | `EmergencyRecovery` | `SecureSharing` |
|---|---|---|
| الملف | `Sources/EmergencyRecovery/EmergencyRecovery.swift` | `Sources/SecureSharing/SecureSharing.swift` |
| `HKDF sharedInfo` | ‏`WezWordn-EmergencyRecovery-v1` | ‏`WezWordn-SecureSharing-v1` |
| النص الصريح | `vaultKey: Data` كما يمرّره المستدعي — الوحدة لا تفترض طولًا ولا مصدرًا له | ‏`JSONEncoder().encode(ShareableItem)` (عنصر واحد: title/username/email/password/notes/url) |
| بنية الحزمة (`Codable`، ‏`version = 1`) | ‏`RecoveryPackage`: ‏ephemeralPublicKey (‏`rawRepresentation`)، ‏salt، ‏nonce، ‏ciphertext، ‏createdAt، ‏ownerLabel | ‏`SharePackage`: نفس الحقول التشفيرية + ‏createdAt + ‏`fingerprint`؛ التصدير/الاستيراد JSON بـ `iso8601` و`sortedKeys`، والامتداد المعلن `wezshare` |
| التحقق قبل/أثناء الفتح | تطابق `version`، ‏`ciphertext.count > 16`، ‏`nonce.count == 12`، ثم نجاح `AES.GCM.open` — مفتاح خاص خاطئ يفشل عند الـ `tag` بـ `decryptionFailed` | نفس الفحوصات **مسبوقة** بفحص البصمة (§3.2): فشلها يرمي `fingerprintMismatch` قبل أي فك تشفير |

### 3.1 ما لا يوجد في أيٍّ من الحزمتين

**لا توقيع رقمي.** لا `Ed25519` ولا أي `Signature` في الوحدتين: لا الحزمة موقّعة من مرسِل، ولا هوية المرسل موثّقة تشفيريًا. السلامة المُثبتة هي سلامة المحتوى ضد التعديل العشوائي/اللاحق عبر `GCM tag` (ومن يعيد بناء حزمة كاملة بمفتاحه الـ ephemeral الخاص يستطيع إنتاج حزمة «سليمة» لأي مستلم — البصمة في §3.2 لا تغيّر ذلك).

### 3.2 بصمة `SecureSharing` — تعريفها وحدّها

```
fingerprint = lowercase-hex SHA-256( ephemeralPublicKey ‖ salt ‖ nonce ‖ ciphertext )
```

(‏`SharePackage.computeFingerprint` — تحديثات متتابعة على `SHA256()` واحد بالترتيب أعلاه.) قيمتها المعلنة في الكود: قيمة عرض/مقارنة خارج النطاق (out-of-band) بين المرسل والمستلم **قبل** الاستيراد. حدّها: بصمة غير مفتاحية (unkeyed) — أي طرف يعيد حسابها على حزمة معدّلة، فهي تكشف التلف والتعديل اللاحق لإنشاء الحزمة، ولا تثبت مصدرًا. `EmergencyRecovery` لا بصمة فيها أصلًا؛ حمايتها الوحيدة هي الـ `GCM tag` تحت المفتاح المشتق.

## 4) ‏`LocalEncryptedStorage` — تنسيق `WZEN v1` المُجزّأ

المصدر: `Sources/LocalEncryptedStorage/LocalEncryptedStorage.swift`. مصمّم للبث (streaming) عبر `FileHandle` — لا يُحمّل الملف كاملًا في الذاكرة في أي مسار.

### 4.1 البنية على القرص (كل الأعداد big-endian)

```
Header (21 bytes):
  magic      4 bytes   ASCII "WZEN"
  version    1 byte    0x01
  baseNonce 12 bytes   عشوائي، جديد لكل عملية تشفير ملف
  chunkSize  4 bytes   UInt32 — بايتات النص الصريح لكل chunk، النطاق المقبول 1 … 16 MiB

ثم سجل لكل chunk، بعدّاد i = 0, 1, 2, …:
  plainLen   4 bytes   UInt32 — ‏1 … chunkSize لسجل بيانات؛
                       0 = سجل نهاية صريح (end-of-stream) بلا ciphertext/tag بعده
  ciphertext plainLen bytes
  tag       16 bytes   ‏GCM tag لذلك الـ chunk وحده
```

القيمة الافتراضية: `defaultChunkSize = 64 KiB` (‏`64 * 1024`). سجل النهاية **إلزامي الوجود**: ملف بلا سجل `plainLen == 0` يُعامل كمبتور/تالف (`truncated`)، ولا يُسلّم كناتج ناجح.

### 4.2 اشتقاق `nonce` لكل chunk — الصيغة الدقيقة

```
chunkNonce(baseNonce, counter):
  nonce = copy(baseNonce)                       // 12 bytes
  nonce[4 ..< 12] XOR= bigEndian(UInt64(counter))   // آخر 8 bytes فقط؛ أول 4 bytes بلا تغيير
```

(‏`chunkNonce(baseNonce:counter:)` في الملف نفسه.) ضمان عدم إعادة الاستخدام كما هو مبني: `baseNonce` عشوائي لكل ملف، والعدّاد وحيد لكل chunk داخل الملف، فيختلف كل زوج `(key, nonce)` عن أي زوج آخر تحت نفس المفتاح — عبر الـ chunks وعبر الملفات. الـ `nonce` الفعلي لا يُخزّن لكل chunk؛ يُعاد اشتقاقه عند الفك من الترويسة والعدّاد.

### 4.3 سلوك الفك والفشل وإعادة المفتاح

- الفك يعيد التحقق من: طول الترويسة (21 بايت بالضبط)، الـ `magic`، الـ `version`، نطاق `chunkSize`، ‏`plainLen ≤ chunkSize` لكل سجل، واكتمال كل `ciphertext` و`tag` قبل بناء `AES.GCM.SealedBox` وفتحه. أي فشل — بما فيه `authenticationFailed` لمفتاح خاطئ أو chunk معدّل — يحذف ملف الناتج الجزئي قبل رمي الخطأ.
- ‏`rekeyFile(at:oldKey:newKey:)`: يفك إلى ملف مؤقت مجاور ثم يعيد التشفير إلى مؤقت ثانٍ، ولا يستبدل الأصل إلا بعد نجاح الخطوتين كاملتين؛ عند أي فشل تُحذف المؤقتات ويبقى الأصل بايتًا ببايت كما كان. `LocalDataVault.rotateStorageKey(to:)` يبني عليه مع محاولة rollback معاكسة للملفات التي دُوّرت فعلًا عند فشل لاحق (موثّق في `LocalDataVault.swift`).

## 5) ‏`LocalDataVault` — الـ sidecar والنسخ الاحتياطي

المصادر: `Sources/LocalDataVault/LocalDataVault.swift`، `PBKDF2.swift`، `VaultBackup.swift`.

### 5.1 ‏`PBKDF2-HMAC-SHA256` — التنفيذ

`PBKDF2.deriveKeySHA256(password:salt:iterations:keyLength: = 32)` ينفّذ RFC 8018 §5.2 حرفيًا فوق `HMAC<SHA256>`:

```
U_1 = PRF(password, salt ‖ INT_32_BE(blockIndex))     // blockIndex يبدأ من 1
U_n = PRF(password, U_{n-1})
T_i = U_1 ⊕ U_2 ⊕ … ⊕ U_iterations
DK  = (T_1 ‖ T_2 ‖ …) مقتطعًا إلى keyLength bytes
```

متجه تحقق معروف (KAT) مثبّت في تعليق الملف ومؤكَّد في الاختبارات: ‏`PBKDF2-HMAC-SHA256(password="password", salt="salt", c=1, dkLen=32) = 120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b`. ‏`precondition`: ‏`iterations ≥ 1` و`keyLength ≥ 1`.

### 5.2 النسخ الاحتياطي `WEZBACKUP v1` — طبقتا التشفير

```
BackupPackage (JSON خارجي — بيانات وصفية فقط، بلا أسرار):
  format        = "WEZBACKUP"
  version       = 1
  kdfSalt       = 16 random bytes، جديد لكل تصدير
  kdfIterations = العدد المستخدم فعليًا (defaultBackupIterations = 210_000، قابل للتمرير)
  sealedPayload = AES.GCM.SealedBox.combined        // nonce ‖ ciphertext ‖ tag
                  تحت مفتاح PBKDF2(password UTF-8, kdfSalt, kdfIterations, 32 bytes)

BackupPayload (النص الصريح بعد الفك، JSON):
  manifest   = عدّادات (emails / TOTPs / files) + storeSHA256 + fileFingerprints
  store      = SidecarStore كاملًا
  fileBlobs  = [fileId : بايتات ملف .wzen كما هو مخزّن]
```

نقاط دقيقة من الكود:

- **`AES.GCM.seal(payloadData, using: key)` هنا بلا `nonce` صريح** — يولّده `swift-crypto` داخليًا ويظهر داخل `combined`. هذا يختلف عن مسارات §3 و§4 التي تبني الـ `nonce` بنفسها (انظر §8.3).
- **الطبقتان مستقلتان:** الـ `fileBlobs` تبقى مشفرة بمفتاح التخزين المحلي (§4) داخل الحزمة؛ كلمة مرور النسخ الاحتياطي **تغلّف الحزمة ولا تشفّر الملفات نفسها من جديد**. تبعة موثّقة في رأس `VaultBackup.swift`: بعد الاستعادة تُفك الملفات بمفتاح التخزين **الحالي** للخزنة المستقبِلة — نسخة احتياطية وحدها، دون ذلك المفتاح، لا تكفي لقراءة الملفات.
- **البصمات:** ‏`storeSHA256` = ‏hex SHA-256 لترميز `store` القانوني (JSON بـ `sortedKeys`)؛ ‏`fileFingerprints[fileId]` = ‏hex SHA-256 لبايتات الـ blob المخزّنة.
- **ترتيب الاستيراد — تحقق كامل قبل أي مساس بالحالة الحية:** صيغة الحزمة ← ‏`PBKDF2` + ‏`AES.GCM.open` (كلمة مرور خاطئة أو أي عبث = خطأ واحد `backupBadPasswordOrCorrupt`، بلا تمييز يسرّب معلومة) ← تطابق العدّادات ← بصمة الـ store ← تطابق مجموعة الـ blobs مع المراجع وبصمة كل blob ← قابلية ترحيل الـ schema (`migrateStore`). عند أي فشل قبل خطوة التطبيق: بيانات الخزنة الحالية **غير معدّلة إطلاقًا** — هذا ضمان منصوص في الكود ومختبَر.

### 5.3 الـ sidecar نفسه

- `vault-sidecar.wzen`: ‏JSON من نوع `SidecarStore` (سجلات البريد الإضافي وأسرار TOTP المحلية ومراجع الملفات، مربوطة بمفتاح مركّب `(accountId, cipherId)`) مشفّر بتنسيق `WZEN v1` نفسه (§4) تحت مفتاح `KeyProvider` — **لا** بكلمة مرور ولا بـ `PBKDF2`. الملفات المرجعية تعيش في `files/<fileId>.wzen` بنفس المخطط والمفتاح.
- ‏`schemaVersion` الحالي = 1؛ ‏`migrateStore` يرفض أي إصدار آخر صراحة بـ `unsupportedSchemaVersion` دون مساس بالبيانات (لا ترحيلات أخرى موجودة بعد، فلا يُدّعى غير ذلك).
- ‏`EncryptedFileRef.sha256`: ‏hex SHA-256 **لنص الملف الصريح**، يُحسب بثًا (قراءة 64 KiB) عند التخزين قبل التشفير — بصمة محتوى، منفصلة عن بصمات الـ blobs في §5.2.
- **أثر جانبي موثّق في الكود:** كتابة/قراءة الـ sidecar تمرّان بملفات نص صريح مؤقتة داخل مجلد الخزنة نفسه (أسماء `.sidecar-plain-*` / `.sidecar-load-*` عشوائية بـ `UUID`)، تُحذف على كل مسارات النجاح والفشل (`defer`) وتُكتب كتابة ذرّية (`.atomic`) قبل التشفير. التنفيذ إذن ليس «صفر ملفات مؤقتة صريحة» — انظر §8.4.

## 6) ‏OTP وHIBP — استخدامات مشروطة بالمعيار

### 6.1 ‏`LocalTOTP` — ‏HOTP (RFC 4226) / TOTP (RFC 6238)

المصدر: `Sources/LocalTOTP/LocalTOTP.swift`، دالّة `OTPGenerator.hotp(secret:counter:digits:algorithm:)`:

```
counterData = bigEndian(UInt64(counter))              // 8 bytes
mac         = HMAC<algorithm>(counterData, key = secret)
offset      = mac[last] & 0x0F                        // dynamic truncation — RFC 4226 §5.3
binary      = (mac[offset] & 0x7F) << 24 | mac[offset+1] << 16
            | mac[offset+2] << 8 | mac[offset+3]
code        = binary mod 10^digits، مهيّأ بصفر بادئ إلى digits خانات
```

- الخوارزميات: `SHA1` (افتراضي)، `SHA256`، `SHA512` — تعداد `OTPAlgorithm` بقيم خام مطابقة لأسماء `otpauth`. الأرقام مقيّدة بـ `6…8` (`invalidDigits` خارجها).
- ‏`totp(secret:date:period:digits:algorithm:)`: ‏`counter = floor(unixTime / period)`، الافتراضي `period = 30` ثانية، و`period ≤ 0` مرفوض (`invalidPeriod`). ‏`remainingSeconds` مشتق حسابي من نفس القسمة.
- ‏`OTPAuthParser.parse` يقبل **`otpauth://totp/` فقط**: يرفض أي scheme آخر وأي host غير `totp` — بما فيه `hotp` كرابط URI (دالّة `hotp` الحسابية موجودة ومختبَرة، لكن لا مسار parsing لها). يرفض أيضًا سرًّا غير Base32، وخوارزمية غير معروفة، وأرقامًا/فترة خارج النطاق.

### 6.2 ‏`HIBPClient` — ‏SHA-1 لأجل البروتوكول فقط

`sha1Hex(of:)` يحسب `Insecure.SHA1` لكلمة المرور محليًا، و`splitHash` يقطع الناتج إلى `prefix` (أول **5 hex chars** = 20 bit) و`suffix` (الباقي، 35 hex chars). وحده الـ prefix يُرسل (§PRIVACY). SHA-1 لا يُستخدم في أي حماية داخل WezWordn — وظيفته هنا هي مطابقة تنسيق HIBP Range API حصرًا.

## 7) تشفير Bitwarden الأصلي — داخل `BitwardenSdk`، خارج هذا الكود

- **لا يوجد تنفيذ Swift لتشفير الخزنة في مستودع `bitwarden/ios` ولا في `WezWordnCore`:** التشفير والمزامنة وتوليد TOTP الخادمي تتم داخل `BitwardenSdk` — غلاف `bitwarden/sdk-swift` (مثبّت عند revision ‏`e98eb30158d3d2239d8bb6e35daf0a3e65db77ec` في لقطة الفحص) فوق هدف ثنائي `BitwardenFFI` بصيغة XCFramework بنواة Rust. الأدلة والمراجع في `ARCHITECTURE.md` §1.4.
- ما تعرضه طبقة Swift عن الـ `KDF` هو تعداد `KdfType` فقط: ‏`PBKDF2-SHA256` (قيمة `0`) و`Argon2id` (قيمة `1`). اختيار النوع ومعلماته (عدد التكرارات، ذاكرة/توازي Argon2id، …) تُدار داخل الـ SDK/حساب الخادم — **ليست موجودة في شيفرة هذا المستودع ولا يمكن التحقق منها منه**، وهذه الوثيقة لا تنسب لها أي قيم عددية.
- بالمثل: الخوارزمية المتماثلة وطريقة التغليف داخل نواة Rust **غير مُتحقق منها من فحص هذا المستودع** (`SOURCE_ANALYSIS.md` يصرّح بذلك) — لا تُنسب لها هنا أي تسمية (لا «AES-256» ولا غيرها) بوصفها حقيقة مدققة من الكود المتاح هنا.
- قاعدة WezWordn الملزمة: لا كود محلي يلمس هذه المسارات أو يعيد تنفيذها أو يضعفها (`FEATURE_MAPPING.md`).

## 8) إدارة المفاتيح (Key Management)

| المفتاح | التوليد | التخزين | العمر / الدوران |
|---|---|---|---|
| مفتاح تخزين الملفات والـ sidecar (32 bytes) | إنتاجيًا: `SecRandomCopyBytes(kSecRandomDefault, 32)` مرة واحدة عند أول طلب — `AppIntegration/KeychainKeyProvider.swift` | ‏Keychain: ‏`kSecClassGenericPassword`، خدمة `com.wezcrypt.wezwordn.local-files`، حساب `file-encryption-key-v1`، ‏`kSecAttrAccessible = kSecAttrAccessibleWhenUnlockedThisDeviceOnly`، ‏`kSecAttrSynchronizable = false` | ثابت حتى `rotateStorageKey(to:)` الصريح (§4.3) أو `deleteKey()` — والحذف يجعل كل ملف `WZEN` غير قابل للفك نهائيًا |
| نفس المفتاح في الاختبارات/خارج iOS | `InMemoryKeyProvider` — إما بيانات يمرّرها المستدعي (تُرفض إن لم تكن 32 bytes) أو توليد افتراضي عبر `UInt8.random` (§8.3) | الذاكرة فقط، بلا أي persistence | عمر العملية |
| مفاتيح X25519 للمستلمين (طوارئ/مشاركة) | `Curve25519.KeyAgreement.PrivateKey()` — توليد `swift-crypto` الداخلي | **الـ Core لا يخزّنها إطلاقًا:** يستقبل المفتاح العام عند الإنشاء والخاص عند الفتح كقيم تمرَّر له. طبقة التكامل الحالية تبقيها في ذاكرة الجلسة (`@State`) فقط — حفظها الدائم المشفر TODO موثّق في `FEATURE_MAPPING.md`، غير منفّذ | بقاءها مسؤولية التطبيق المضيف |
| مفاتيح X25519 الـ ephemeral | `Curve25519.KeyAgreement.PrivateKey()` لكل حزمة | لا تُحفظ؛ يُنشر المفتاح العام وحده داخل الحزمة | حزمة واحدة ثم تُرمى |
| مفتاح النسخ الاحتياطي | `PBKDF2-HMAC-SHA256` من كلمة مرور يختارها المستخدم لكل تصدير (§5) | لا يُخزّن في أي مكان؛ يُعاد اشتقاقه عند الاستيراد من (`password`, `kdfSalt`, `kdfIterations`) داخل الحزمة | تصدير واحد |
| مفاتيح/جلسات حساب Bitwarden | داخل `BitwardenSdk` وخدمات upstream (`KeychainService` وغيرها) | آليات upstream كما هي | خارج نطاق WezWordn — لم تُعدَّل |

تبعات `WhenUnlockedThisDeviceOnly` الموثّقة في رأس `KeychainKeyProvider.swift` و`SECURITY.md` §2.5: المفتاح غير قابل للقراءة والجهاز مقفل، ولا يهاجر مع النسخ الاحتياطية إلى جهاز آخر، ولا يتزامن إلى iCloud Keychain. استعادة ملفات `WZEN` على جهاز جديد دون المفتاح = ملفات غير قابلة للفك، وهذا سلوك مقصود وموثّق للمستخدم في `SECURITY.md`.

### 8.1 حدود صريحة — ما **ليس** منفّذًا حاليًا

1. **لا Secure Enclave wrapping في الـ Core ولا في `AppIntegration`:** بحث الشيفرة لا يجد أي استخدام لـ `SecureEnclave` أو مفاتيح مقيمة في الـ Enclave. حماية مفتاح التخزين قائمة على `Keychain` + فئة الوصول أعلاه وحماية بيانات نظام iOS — لا يُدّعى أكثر من ذلك. (المطلوب الأصلي «استخدام Secure Enclave عند ملاءمة التصميم» بقي قرارًا غير منفّذ، لا قدرة قائمة.)
2. **لا `Argon2id` في أي مسار محلي:** الـ sidecar محمي بمفتاح عشوائي في Keychain (ليس مشتقًا من Master Password بأي KDF)، والنسخ الاحتياطي يستخدم `PBKDF2-HMAC-SHA256` فقط (§5). ‏`Argon2id` موجود حصرًا كخيار `KdfType` داخل `BitwardenSdk` لحساب Bitwarden (§7).
3. **العشوائية عبر `UInt8.random(in: 0...255)`:** القيم التالية تُبنى بايتًا-بايت بهذه الدالّة في الكود الحالي — ‏`WZEN baseNonce` ‏(12B)، مفتاح `InMemoryKeyProvider` الافتراضي (32B)، ‏`salt` الحزم (32B) و`nonce` الحزم (12B) في الوحدتين، ‏`kdfSalt` النسخ الاحتياطي (16B): ‏`LocalEncryptedStorage.swift`، `EmergencyRecovery.swift`، `SecureSharing.swift`، `VaultBackup.swift`. في Swift تعتمد `UInt8.random` على `SystemRandomNumberGenerator` للنظام (موثّق في `SECURITY.md` §3 بوصفه مولّد النظام الآمن)، لكن الكود لا يستدعي واجهة CSPRNG صريحة في هذه المواضع — على خلاف مفتاح الإنتاج في Keychain (‏`SecRandomCopyBytes`) ومفاتيح Curve25519 والـ `nonce` الداخلي لختم النسخ الاحتياطي (توليد داخل `swift-crypto`). توحيد هذه المواضع على واجهة صريحة بند تدقيق مفتوح موثّق في `SECURITY.md`، لم يُنفّذ بعد.
4. **ملفات مؤقتة بصيغة صريحة:** فك/تشفير الملفات ومعاينتها وكتابة الـ sidecar تمر بملفات مؤقتة؛ الخاصة بالـ sidecar داخل مجلد الخزنة وتُحذف على كل المسارات (§5.3)، لكن لا يوجد مسح آمن (secure wipe) لها ولا ضمان محو فيزيائي من flash — انظر `SECURITY.md` §4.1.
5. **لا توقيع على الحزم** (§3.1)، **ولا فترة انتظار/إلغاء** لحزم الطوارئ أو المشاركة بعد التسليم (`SECURITY.md` §4.2–4.3).
6. **أسرار TOTP المحلية دائمة التخزين فقط عبر `LocalDataVault`** (داخل الـ sidecar المشفر، §5.3)؛ شاشة التكامل الحالية تبقي أسرارها في ذاكرة الجلسة فقط — انظر `FEATURE_MAPPING.md`.
