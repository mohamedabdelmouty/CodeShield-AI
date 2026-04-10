# دليل النشر / Publishing Guide

## بالعربي

### المتطلبات
- حساب على [npm](https://www.npmjs.com)
- حساب على [Azure DevOps](https://dev.azure.com) (لنشر الإضافة على VS Code Marketplace)
- مستودع GitHub باسم `vibeguard/vibeguard` (أو حدّث روابط `repository` في كل `package.json`)

### ترتيب النشر (مهم)
1. **Core** أولاً → ثم **CLI** → ثم **Extension** (لأن الإضافة والـ CLI يعتمدان على Core المنشور).

---

### 1) نشر Core على npm
```bash
cd vibeguard/core
npm run build
npm login
npm publish --access public
```
- الحزمة المنشورة: `@vibeguard/core`
- الرابط بعد النشر: https://www.npmjs.com/package/@vibeguard/core

---

### 2) نشر CLI على npm
```bash
cd vibeguard/cli
npm run build
npm login
npm publish
```
- الحزمة المنشورة: `vibeguard`
- الناس تنزّل وتشغّل: `npx vibeguard scan .` أو `npm install -g vibeguard`
- الرابط: https://www.npmjs.com/package/vibeguard

**ملاحظة:** إذا الاسم `vibeguard` محجوز على npm، غيّر `name` في `cli/package.json` إلى مثلاً `vibeguard-cli` أو `@vibeguard/cli` ثم انشر.

---

### 3) نشر الإضافة على VS Code Marketplace
1. إنشاء **Publisher** (مرة واحدة):
   - ادخل إلى https://marketplace.visualstudio.com
   - Sign in بحساب Microsoft
   - اضغط **Publish extension** → **Create Publisher** واختر اسم (مثلاً `vibeguard`)

2. إنشاء **Personal Access Token** من Azure DevOps:
   - https://dev.azure.com → User Settings → Personal Access Tokens
   - New Token مع صلاحية **Packaging (Read & write)**

3. نشر الإضافة:
```bash
cd vibeguard/vscode-extension
npm install
npm run compile
npx vsce login vibeguard
npx vsce publish
```
أو باستخدام التوكن:
```bash
npx vsce publish -p YOUR_PERSONAL_ACCESS_TOKEN
```

- بعد النشر تظهر الإضافة في VS Code عند البحث عن "VibeGuard Security Scanner".

---

### تحديث إصدار لاحق
- زِد رقم `version` في الـ `package.json` المعني (core / cli / vscode-extension) ثم نفّذ نفس أوامر النشر.

---

## English

### Requirements
- [npm](https://www.npmjs.com) account
- [Azure DevOps](https://dev.azure.com) account (for VS Code Marketplace)
- GitHub repo `vibeguard/vibeguard` (or update `repository` URLs in each `package.json`)

### Publish order (important)
1. **Core** first → then **CLI** → then **Extension** (extension and CLI depend on published Core).

---

### 1) Publish Core to npm
```bash
cd vibeguard/core
npm run build
npm login
npm publish --access public
```
- Package: `@vibeguard/core`
- Page: https://www.npmjs.com/package/@vibeguard/core

---

### 2) Publish CLI to npm
```bash
cd vibeguard/cli
npm run build
npm login
npm publish
```
- Package: `vibeguard`
- Users run: `npx vibeguard scan .` or `npm install -g vibeguard`
- Page: https://www.npmjs.com/package/vibeguard

**Note:** If the name `vibeguard` is taken on npm, change `name` in `cli/package.json` to e.g. `vibeguard-cli` or `@vibeguard/cli`, then publish.

---

### 3) Publish Extension to VS Code Marketplace
1. Create a **Publisher** (one-time):
   - Go to https://marketplace.visualstudio.com
   - Sign in with Microsoft
   - Click **Publish extension** → **Create Publisher** and choose a name (e.g. `vibeguard`)

2. Create a **Personal Access Token** in Azure DevOps:
   - https://dev.azure.com → User Settings → Personal Access Tokens
   - New Token with **Packaging (Read & write)** scope

3. Publish:
```bash
cd vibeguard/vscode-extension
npm install
npm run compile
npx vsce login vibeguard
npx vsce publish
```
Or with token:
```bash
npx vsce publish -p YOUR_PERSONAL_ACCESS_TOKEN
```

- The extension will appear in VS Code when searching for "VibeGuard Security Scanner".

---

### Updating a version later
- Bump `version` in the relevant `package.json` (core / cli / vscode-extension), then run the same publish commands.
