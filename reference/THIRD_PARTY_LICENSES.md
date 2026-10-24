# THIRD_PARTY_LICENSES — تراخيص المكوّنات الخارجية

> هذا الملف **فهرس إشعارات** لا نسخة من نصوص التراخيص: يذكر لكل مكوّن خارجي ترخيصه والإشعار المطلوب الاحتفاظ به ومكان النص الملزم. النص الكامل الوحيد المحفوظ داخل هذا المستودع هو ملف `LICENSE` في الجذر (§1). كل مكوّن غير مذكور هنا إما كود أصلي لهذا المشروع (يخضع لترخيص المشروع — GPLv3، انظر `README.md`) أو تبعية upstream عابرة يحكمها إشعارها الأصلي في مستودعها (§5).

---

## 0) ملخص

| # | المكوّن | الدور في WezWordn | الترخيص | حالة الفحص |
|---|---|---|---|---|
| 1 | ‏`bitwarden/ios` | الأساس الكامل للتطبيق: الواجهة والخزنة والامتدادات، يُبنى دون تعديل جوهري في تنسيقاته | **GNU GPLv3** | مؤكد — نص الترخيص في `LICENSE` |
| 2 | ‏`apple/swift-crypto` | التبعية الخارجية الوحيدة لـ `WezWordnCore`: ‏AES-GCM، ‏Curve25519، ‏HKDF، ‏HMAC، ‏SHA | **Apache License 2.0** | مؤكد — `DEPENDENCY_REPORT.md` + ملف الترخيص في مستودع Apple |
| 3 | ‏`BitwardenSdk` (‏`bitwarden/sdk-swift` ‏/ ‏`BitwardenFFI`) | نواة التشفير والمزامنة وكلمة المرور الأصلية (Rust FFI) | **غير محسوم — بند مفتوح** | لم يُفحص فحصًا كاملًا مستقلًا بعد (§3) |
| 4 | ‏`morluto/rea` (‏`rea-agents`) | أداة تحليل/هندسة عكسية أثناء التطوير فقط — **ليست** تبعية تشغيل ولا تُشحن داخل التطبيق | **MIT** | مؤكد من README المستودع و`REA_ANALYSIS.md` §7 |

## 1) ‏Bitwarden iOS — ‏GNU GPLv3

- **المصدر:** ‏`https://github.com/bitwarden/ios` — لقطة الفحص على فرع `main` عند commit ‏`901bd4de8dbd9f5f7ba11b69499dd618feb0933c` (انظر `ARCHITECTURE.md`).
- **النص الملزم:** ملف `LICENSE` في جذر هذا المستودع — نسخة حرفية من ملف `LICENSE.txt` الأصلي في upstream، وهو النص الكامل لـ GNU General Public License v3 (29 June 2007). أي إشارة إلى «GPLv3» في وثائق المشروع تعني ذلك الملف.
- **الإشعار المطلوب ومتطلبات التوزيع** (كما تلخّصها `README.md`، ولا يغني هذا التلخيص عن نص الترخيص):
  1. الاحتفاظ بإشعارات حقوق المؤلف وإشعارات الترخيص الموجودة في الشيفرة المصدرية كما هي.
  2. توفير الشيفرة المصدرية المقابلة كاملة (upstream + تعديلات وإضافات WezWordn) تحت نفس الترخيص مع أي توزيع لنسخة مبنية، بما فيها أي ملف IPA.
  3. ترخيص العمل المشتق ككل تحت GPLv3 عند التوزيع، وعدم فرض قيود إضافية على حقوق المستلمين بموجبه.
  4. **عدم الانتساب والعلامات:** WezWordn مشروع مشتق غير رسمي؛ لا يُقدَّم على أنه منتج من Bitwarden, Inc. ولا يستخدم علاماتها التجارية اسمًا أو هوية له (الاسم والـ bundle ID ‏`com.wezcrypt.wezwordn` مستقلان). التزام العلامات التجارية منفصل عن ترخيص الشيفرة ولا يمنحه الترخيص.

## 2) ‏Apple swift-crypto — ‏Apache License 2.0

- **المصدر:** ‏`https://github.com/apple/swift-crypto` — مصرّح به في `WezWordnCore/Package.swift` بمتطلب `from: "3.0.0"`، ومثبّت فعليًا في `WezWordnCore/Package.resolved`. تبعية عابرة موثّقة في نفس الملف: ‏`apple/swift-asn1` (تُستخدم داخل swift-crypto) وتخضع لترخيص مستودعها الأصلي.
- **الاستخدام:** منتج `Crypto` فقط — ‏AES-256-GCM، ‏Curve25519 (X25519)، ‏HKDF-SHA256، ‏HMAC، ‏SHA-1/256/512 (انظر `CRYPTOGRAPHY.md` §2). لا تعديل على شيفرة المكتبة.
- **الإشعار المطلوب بموجب Apache-2.0 (تلخيص — النص الملزم في ملف `LICENSE` داخل مستودع المكتبة):**
  1. تضمين نسخة من ترخيص Apache-2.0 مع أي توزيع يضم المكتبة.
  2. الاحتفاظ بكل إشعارات حقوق المؤلف والبراءات والعلامات والإسناد في المصدر أو في وثائق التوزيع.
  3. إن وُجد ملف `NOTICE` في المكتبة وجب تضمين نصه المنسوب في المشتقات.
  4. وسم الملفات المعدّلة بإشعار تغيير — **لا ينطبق حاليًا**: المكتبة تُستخدم غير معدّلة.
  5. الترخيص لا يمنح حق استخدام علامات Apple التجارية، ويقدَّم العمل «كما هو» بلا ضمانات وفق بنود الترخيص نفسه.

## 3) ‏BitwardenSdk — بند ترخيص مفتوح (Open Item)

- **المكوّن:** ‏`bitwarden/sdk-swift` عند revision ‏`e98eb30158d3d2239d8bb6e35daf0a3e65db77ec`، من خلفه الهدف الثنائي `BitwardenFFI` بنواة من مستودع `bitwarden/sdk`. به تتم كل عمليات تشفير الخزنة الأصلية والمزامنة (`CRYPTOGRAPHY.md` §7).
- **الحالة الصريحة:** فحص ترخيص هذه المكوّنات الثنائية فحصًا كاملًا مستقلًا **لم يُنجز بعد**. هذا التحفظ موثّق بنفس الصيغة في ثلاثة مواضع سابقة: `README.md` (قسم الترخيص)، `DEPENDENCY_REPORT.md`، و`SECURITY.md` §4.7 — وهذا الملف يرثه ولا يحسمه.
- **تبعًا لذلك:**
  - لا يُنسب إلى `BitwardenSdk` في أي وثيقة من وثائق المشروع ترخيص بعينه (لا GPL ولا غيره) بوصفه حقيقة مؤكدة.
  - لا يُكتب له هنا «نص إشعار مطلوب»، لأن اشتقاق إشعار من ترخيص غير مُتحقق منه اختلاق.
  - حسم هذا البند — قراءة ملفات الترخيص الفعلية في مستودعي `sdk-swift` و`sdk` وتوثيق النتيجة هنا — **شرط قبل أي توزيع خارجي واسع** لنسخ مبنية من WezWordn.

## 4) ‏REA (‏`morluto/rea`) — ‏MIT

- **المصدر:** ‏`https://github.com/morluto/rea` — حزمة `rea-agents` (الإصدار المرصود وقت الفحص: `6.7.0`)؛ الموقع الرسمي `https://rea.tools`. التفاصيل المرصودة في `REA_ANALYSIS.md` §7.
- **طبيعة العلاقة بالمشروع:** أداة تطوير/تحليل (MCP server + CLI) على جهاز المطوّر، كأدوات Ghidra/IDA التي تربط بها. **لا تُبنى داخل التطبيق، ولا تُربط به، ولا تُوزَّع معه.** وفي بيئة إنشاء هذا الهيكل لم تُثبّت ولم تُشغَّل أصلًا (الأسباب موثّقة في `REA_ANALYSIS.md` §7) — ذكرها هنا التزام شفافية عن أدوات التطوير، لا تبعية.
- **الإشعار المطلوب بموجب MIT (النص الملزم في ملف الترخيص داخل مستودع الأداة):** الاحتفاظ بإشعار حقوق المؤلف التالي وبنص إذن MIT في أي نسخ أو أجزاء جوهرية من الأداة نفسها عند إعادة توزيعها:
  > Copyright (c) 2026 morluto
  >
  > Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
  >
  > THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.

  (الفقرة الأخيرة إخلاء الضمان القياسي في MIT — تُعاد كتابتها من قالب MIT المعروف، وعند أي تعارض يحكم النص الموجود في مستودع الأداة نفسه.)

## 5) تبعيات upstream الأخرى — ملاحظة نطاق

لقطة upstream تحمل تبعيات إضافية مثبّتة في `Package.resolved` الخاص بها ومذكورة في `ARCHITECTURE.md` §1.5: ‏`Firebase 12.14.0` (‏`FirebaseCrashlytics`)، وتبعيات اختبار/بناء (‏`SnapshotTesting`، ‏`ViewInspector`، ‏`SwiftProtobuf`، ‏`SwiftUIIntrospect`). هذه المكوّنات:

- لم يضفها مشروع WezWordn ولم يعدّلها؛ تدخل البناء بحكم كونها جزءًا من upstream كما هو.
- تخضع كلٌّ منها لترخيصها وإشعاراتها الأصلية في مستودعها، ويبقى الالتزام بها كما تفرضه تلك النصوص عند التوزيع.
- فهرستها فرديًا بنصوص إشعاراتها الموثّقة لم يُنجز ضمن هذا الملف؛ ما ورد أعلاه (§1–§4) يغطي المكوّنات التي تناولتها مهمة التوثيق هذه صراحة. إكمال فهرس كامل (SBOM بتراخيص كل pin) بند توثيق مفتوح الى جانب بند §3، ولا يُدّعى اكتماله هنا.
