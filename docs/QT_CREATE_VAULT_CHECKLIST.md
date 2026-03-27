# Qt Create Vault Manual Checklist

Use this checklist to verify the pre-login chooser and new vault creation flow in the Qt desktop app.

## Test Setup

- Run the app in Qt mode.
- Prepare one empty temp folder for test key/DB files.
- If testing USB mode, connect a removable drive and use a path on that drive.

## Checklist

1. Startup chooser is shown before login.
- Expected: Dialog shows choices for Login to Existing Vault and Create New Vault.

2. Login branch still works.
- Steps: Choose Login to Existing Vault and complete a normal login.
- Expected: Existing vault opens as before.

3. Create branch opens create dialog.
- Steps: Restart app, choose Create New Vault.
- Expected: Dialog shows master password, confirm password, key path, DB path, and USB option.

4. Password confirmation validation.
- Steps: Enter mismatched password and confirmation, then submit.
- Expected: Validation error is shown, vault is not created.

5. Required fields validation.
- Steps: Leave key path or DB path blank and submit.
- Expected: Validation error is shown, vault is not created.

6. Create new vault without USB mode.
- Steps: Use normal local paths, USB option disabled, submit.
- Expected: Vault is created, app opens vault window, key and DB files exist.

7. Immediate vault usage after creation.
- Steps: Add one password entry in opened vault.
- Expected: Entry is saved and appears in list.

8. Overwrite prompt when targets already exist.
- Steps: Try creating a vault again using the same key/DB paths.
- Expected: Overwrite confirmation prompt appears.

9. Overwrite prompt cancel path.
- Steps: In overwrite prompt, click No.
- Expected: Creation is canceled and existing files remain unchanged.

10. Overwrite prompt confirm path.
- Steps: Retry and click Yes on overwrite prompt.
- Expected: Vault creation succeeds and app opens vault window.

11. USB mode validation for non-removable path.
- Steps: Enable USB option but use a non-removable key path.
- Expected: Validation error indicates removable media is required.

12. USB mode success path.
- Steps: Enable USB option and use removable drive key path.
- Expected: Vault creation succeeds and key file is written to removable media.

## Regression Notes

- Confirm existing auth token/login API behavior is unchanged.
- Confirm existing CRUD operations still work for both login and newly created vault sessions.
