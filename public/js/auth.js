document.addEventListener('DOMContentLoaded', () => {
  'use strict';

  const tabLogin = document.getElementById('tab-login');
  const tabRegister = document.getElementById('tab-register');
  const loginForm = document.getElementById('login-form');
  const registerForm = document.getElementById('register-form');
  const authAlert = document.getElementById('auth-alert');

  const deviceModal = document.getElementById('device-modal');
  const deviceModalTitle = document.getElementById('device-modal-title');
  const deviceModalSubtitle = document.getElementById('device-modal-subtitle');
  const deviceVerifyForm = document.getElementById('device-verify-form');
  const deviceOtpInput = document.getElementById('device-otp-input');
  const devOtpBanner = document.getElementById('dev-otp-banner');
  const deviceModalError = document.getElementById('device-modal-error');
  const deviceModalSuccess = document.getElementById('device-modal-success');
  const replaceDeviceSection = document.getElementById('replace-device-section');
  const replaceDeviceNotice = document.getElementById('replace-device-notice');
  const replaceDeviceList = document.getElementById('replace-device-list');
  const closeDeviceModal = document.getElementById('close-device-modal');

  const adminApprovalSection = document.getElementById('admin-approval-section');
  const approvalDeviceList = document.getElementById('approval-device-list');
  const approvalPendingNotice = document.getElementById('approval-pending-notice');
  const deviceRequestForm = document.getElementById('device-request-form');
  const deviceChangeReason = document.getElementById('device-change-reason');
  const requestApprovalSubmit = document.getElementById('request-approval-submit');
  const closeApprovalModal = document.getElementById('close-approval-modal');

  let currentPendingToken = null;
  let currentApprovalToken = null;
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
        return;
      }
      if (result.status === 'approval-required') {
        openApprovalModal(result);
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

  function openApprovalModal(data) {
    currentApprovalToken = data.approvalToken;
    currentPendingToken = null;
    currentAtLimit = false;
    deviceModalError.hidden = true;
    deviceModalSuccess.hidden = true;
    devOtpBanner.hidden = true;
    deviceVerifyForm.hidden = true;
    adminApprovalSection.hidden = false;

    deviceModalTitle.textContent = '🔒 يتطلب موافقة الإدارة لتغيير الجهاز';
    deviceModalSubtitle.textContent = 'الحساب مرتبط بالفعل بجهازين مسموح بهما (2/2).';

    approvalDeviceList.innerHTML = '';
    (data.devices || []).forEach((d) => {
      const item = document.createElement('div');
      item.style.cssText = 'padding:0.55rem 0.7rem;border:1px solid var(--border);border-radius:8px;background:var(--surface-2);font-size:0.86rem;';
      item.textContent = `💻 ${d.label} (آخر ظهور: ${d.lastSeenAt || 'الآن'})`;
      approvalDeviceList.appendChild(item);
    });

    approvalPendingNotice.hidden = !data.hasPendingRequest;
    deviceChangeReason.value = '';
    requestApprovalSubmit.disabled = false;
    requestApprovalSubmit.textContent = data.hasPendingRequest
      ? '🔄 تحديث طلب الموافقة لدى الإدارة'
      : '📩 إرسال طلب موافقة للإدارة';

    deviceModal.hidden = false;
  }

  function openDeviceModal(data) {
    currentPendingToken = data.pendingToken;
    currentApprovalToken = null;
    currentAtLimit = Boolean(data.atLimit && data.canReplace);
    deviceModalError.hidden = true;
    deviceModalSuccess.hidden = true;
    adminApprovalSection.hidden = true;
    deviceVerifyForm.hidden = false;
    deviceOtpInput.value = '';

    deviceModalTitle.textContent = '🔐 تأكيد إضافة جهاز جديد';
    deviceModalSubtitle.textContent = 'تم رصد تسجيل دخول من جهاز جديد. يرجى إدخال الكود المكون من 6 أرقام المرسل إلى بريدك الإلكتروني.';

    if (data.devCodeHint) {
      devOtpBanner.textContent = `وضع الاختبار المحلي — كود التحقق المباشر هو: ${data.devCodeHint}`;
      devOtpBanner.hidden = false;
      deviceOtpInput.value = data.devCodeHint;
    } else {
      devOtpBanner.hidden = true;
    }

    if (currentAtLimit && Array.isArray(data.devices)) {
      replaceDeviceSection.hidden = false;
      replaceDeviceNotice.textContent = data.isAdmin
        ? 'تم بلوغ حد العرض (2/2). بصفتك المدير يمكنك تأكيد كود البريد الإلكتروني واستبدال أي جهاز أدناه بلا قيود:'
        : 'تمت موافقة الإدارة على استبدال جهاز واحد. اختر الجهاز الذي تريد استبداله ثم أدخل كود البريد الإلكتروني:';
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

  closeApprovalModal?.addEventListener('click', () => {
    deviceModal.hidden = true;
  });

  deviceRequestForm?.addEventListener('submit', async (e) => {
    e.preventDefault();
    deviceModalError.hidden = true;
    deviceModalSuccess.hidden = true;
    requestApprovalSubmit.disabled = true;
    try {
      const res = await CourseSecurityClient.requestDeviceChange(
        currentApprovalToken,
        deviceChangeReason.value.trim()
      );
      approvalPendingNotice.hidden = false;
      deviceModalSuccess.textContent = res.alreadyPending
        ? 'تم تحديث طلبك القائم لدى الإدارة بنجاح. سيتم إشعارك فور الموافقة.'
        : 'تم إرسال طلب تغيير الجهاز إلى الإدارة بنجاح. فور موافقة الإدارة يمكنك تسجيل الدخول واستلام كود التحقق على بريدك.';
      deviceModalSuccess.hidden = false;
      requestApprovalSubmit.textContent = '✓ تم إرسال الطلب للإدارة';
    } catch (err) {
      deviceModalError.textContent = err.message;
      deviceModalError.hidden = false;
      requestApprovalSubmit.disabled = false;
    }
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
