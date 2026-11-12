document.addEventListener('DOMContentLoaded', () => {
  'use strict';

  const tabLogin = document.getElementById('tab-login');
  const tabRegister = document.getElementById('tab-register');
  const loginForm = document.getElementById('login-form');
  const registerForm = document.getElementById('register-form');
  const authAlert = document.getElementById('auth-alert');

  const deviceModal = document.getElementById('device-modal');
  const deviceVerifyForm = document.getElementById('device-verify-form');
  const deviceOtpInput = document.getElementById('device-otp-input');
  const devOtpBanner = document.getElementById('dev-otp-banner');
  const deviceModalError = document.getElementById('device-modal-error');
  const replaceDeviceSection = document.getElementById('replace-device-section');
  const replaceDeviceList = document.getElementById('replace-device-list');
  const changesLeftCount = document.getElementById('changes-left-count');
  const closeDeviceModal = document.getElementById('close-device-modal');

  let currentPendingToken = null;
  let currentAtLimit = false;

  function showAlert(msg, isSuccess = false) {
    authAlert.textContent = msg;
    authAlert.className = isSuccess ? 'alert alert-success' : 'alert alert-error';
    authAlert.hidden = false;
  }

  function hideAlert() {
    authAlert.hidden = true;
  }

  tabLogin.addEventListener('click', () => {
    tabLogin.classList.add('active');
    tabRegister.classList.remove('active');
    loginForm.hidden = false;
    registerForm.hidden = true;
    hideAlert();
  });

  tabRegister.addEventListener('click', () => {
    tabRegister.classList.add('active');
    tabLogin.classList.remove('active');
    registerForm.hidden = false;
    loginForm.hidden = true;
    hideAlert();
  });

  // Login Handler
  loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideAlert();
    const btn = document.getElementById('login-submit');
    btn.disabled = true;
    try {
      const email = document.getElementById('login-email').value.trim();
      const password = document.getElementById('login-password').value;
      const result = await CourseSecurityClient.login(email, password);

      if (result.status === 'ok') {
        location.href = result.role === 'admin' ? '/admin' : '/portal';
        return;
      }

      if (result.status === 'verify-device') {
        openDeviceModal(result);
      }
    } catch (err) {
      showAlert(err.message);
    } finally {
      btn.disabled = false;
    }
  });

  // Register Handler
  registerForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideAlert();
    const btn = document.getElementById('reg-submit');
    btn.disabled = true;
    try {
      const fullName = document.getElementById('reg-name').value.trim();
      const email = document.getElementById('reg-email').value.trim();
      const phone = document.getElementById('reg-phone').value.trim();
      const password = document.getElementById('reg-password').value;
      const activationCode = document.getElementById('reg-code').value.trim();

      await CourseSecurityClient.register({ fullName, email, phone, password, activationCode });
      location.href = '/portal';
    } catch (err) {
      showAlert(err.message);
    } finally {
      btn.disabled = false;
    }
  });

  function openDeviceModal(data) {
    currentPendingToken = data.pendingToken;
    currentAtLimit = Boolean(data.atLimit);
    deviceModalError.hidden = true;
    deviceOtpInput.value = '';

    if (data.devCodeHint) {
      devOtpBanner.textContent = `وضع الاختبار المجاني — كود التحقق المباشر هو: ${data.devCodeHint}`;
      devOtpBanner.hidden = false;
      deviceOtpInput.value = data.devCodeHint;
    } else {
      devOtpBanner.hidden = true;
    }

    if (currentAtLimit && Array.isArray(data.devices)) {
      replaceDeviceSection.hidden = false;
      changesLeftCount.textContent = String(data.changesLeft ?? 0);
      replaceDeviceList.innerHTML = '';
      data.devices.forEach((d, idx) => {
        const label = document.createElement('label');
        label.style.cssText = 'display:flex;align-items:center;gap:0.6rem;padding:0.65rem;border:1px solid var(--border);border-radius:8px;cursor:pointer;background:var(--surface-2);';
        const radio = document.createElement('input');
        radio.type = 'radio';
        radio.name = 'replaceDeviceId';
        radio.value = String(d.id);
        if (idx === 0) radio.checked = true;
        const text = document.createElement('span');
        text.textContent = `${d.label} (آخر ظهور: ${d.lastSeenAt || 'الآن'})`;
        label.appendChild(radio);
        label.appendChild(text);
        replaceDeviceList.appendChild(label);
      });
    } else {
      replaceDeviceSection.hidden = true;
    }

    deviceModal.hidden = false;
  }

  closeDeviceModal.addEventListener('click', () => {
    deviceModal.hidden = true;
  });

  deviceVerifyForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    deviceModalError.hidden = true;
    try {
      let replaceId = null;
      if (currentAtLimit) {
        const checked = replaceDeviceList.querySelector('input[name="replaceDeviceId"]:checked');
        if (!checked) {
          deviceModalError.textContent = 'يرجى اختيار جهاز لاستبداله.';
          deviceModalError.hidden = false;
          return;
        }
        replaceId = Number(checked.value);
      }
      const res = await CourseSecurityClient.verifyDevice(
        currentPendingToken,
        deviceOtpInput.value.trim(),
        replaceId
      );
      location.href = res.role === 'admin' ? '/admin' : '/portal';
    } catch (err) {
      deviceModalError.textContent = err.message;
      deviceModalError.hidden = false;
    }
  });
});
