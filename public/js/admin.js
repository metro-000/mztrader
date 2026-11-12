document.addEventListener('DOMContentLoaded', async () => {
  'use strict';

  const alertBox = document.getElementById('admin-alert');

  function notify(msg, isError = false) {
    alertBox.textContent = msg;
    alertBox.className = isError ? 'alert alert-error' : 'alert alert-success';
    alertBox.hidden = false;
    setTimeout(() => { alertBox.hidden = true; }, 4500);
  }

  // Tab Switching
  document.querySelectorAll('[data-admin-tab]').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('[data-admin-tab]').forEach((b) => b.classList.remove('active'));
      document.querySelectorAll('.admin-tab-panel').forEach((p) => { p.hidden = true; });
      btn.classList.add('active');
      const panel = document.getElementById(btn.dataset.adminTab);
      if (panel) panel.hidden = false;
    });
  });

  // Load Overview
  async function loadAdminData() {
    try {
      const data = await CourseSecurityClient.call('/api/admin/overview');
      renderKpis(data);
      renderUsersTable(data.users);
      renderCodesTable(data.activationCodes);
      renderCourseManager(data.course);
      renderSecurityQueue(data.users);
      renderOtpTable(data.otpLogs);
    } catch (err) {
      if (err.status === 401 || err.status === 403) {
        location.href = '/';
        return;
      }
      notify(err.message, true);
    }
  }

  function renderKpis(data) {
    const users = data.users || [];
    const codes = data.activationCodes || [];
    document.getElementById('kpi-total-users').textContent = String(users.length);
    document.getElementById('kpi-enrolled-users').textContent = String(users.filter((u) => u.is_enrolled).length);
    document.getElementById('kpi-review-users').textContent = String(users.filter((u) => u.needs_review || u.risk_score >= 50).length);
    document.getElementById('kpi-available-codes').textContent = String(codes.filter((c) => !c.used_by_user_id).length);
  }

  // ── Tab 1: Users & Activation Codes ──────────────────────────────
  function renderUsersTable(users) {
    const tbody = document.getElementById('admin-users-tbody');
    tbody.innerHTML = '';

    users.forEach((u) => {
      const tr = document.createElement('tr');

      const tdUser = document.createElement('td');
      tdUser.innerHTML = `<div style="font-weight:700;">${escapeHtml(u.full_name)}</div>
        <div style="font-size:0.8rem;color:var(--text-muted);">${escapeHtml(u.email)} ${u.phone ? `• ${escapeHtml(u.phone)}` : ''}</div>`;

      const tdWm = document.createElement('td');
      tdWm.innerHTML = `<span class="badge badge-wm">${escapeHtml(u.watermark_code)}</span>`;

      const tdDev = document.createElement('td');
      tdDev.textContent = `${u.device_count} / 2`;

      const tdRisk = document.createElement('td');
      const riskClass = u.risk_score >= 100 ? 'badge-crimson' : u.risk_score >= 50 ? 'badge-amber' : 'badge-emerald';
      tdRisk.innerHTML = `<span class="badge ${riskClass}">${u.risk_score} نقطة</span>`;

      const tdEnroll = document.createElement('td');
      if (u.is_banned) {
        tdEnroll.innerHTML = '<span class="badge badge-crimson">محظور</span>';
      } else if (u.is_enrolled) {
        tdEnroll.innerHTML = '<span class="badge badge-emerald">مفعل</span>';
      } else {
        tdEnroll.innerHTML = '<span class="badge badge-amber">غير مفعل</span>';
      }

      const tdActions = document.createElement('td');
      const wrap = document.createElement('div');
      wrap.style.cssText = 'display:flex;gap:0.4rem;flex-wrap:wrap;';

      const enrollBtn = document.createElement('button');
      enrollBtn.className = u.is_enrolled ? 'btn btn-outline btn-sm' : 'btn btn-emerald btn-sm';
      enrollBtn.textContent = u.is_enrolled ? 'إلغاء التفعيل' : 'تفعيل الاشتراك';
      enrollBtn.addEventListener('click', async () => {
        await CourseSecurityClient.call(`/api/admin/users/${u.id}/toggle-enroll`, {
          method: 'POST',
          json: { enroll: !u.is_enrolled },
        });
        notify('تم تحديث حالة الاشتراك بنجاح.');
        await loadAdminData();
      });

      const banBtn = document.createElement('button');
      banBtn.className = u.is_banned ? 'btn btn-outline btn-sm' : 'btn btn-primary btn-sm';
      banBtn.textContent = u.is_banned ? 'فك الحظر' : 'حظر';
      banBtn.addEventListener('click', async () => {
        await CourseSecurityClient.call(`/api/admin/users/${u.id}/ban`, {
          method: 'POST',
          json: { isBanned: !u.is_banned, reason: 'قرار إداري من لوحة التحكم' },
        });
        notify(u.is_banned ? 'تم فك الحظر عن الحساب.' : 'تم حظر الحساب وسحب جميع الجلسات.');
        await loadAdminData();
      });

      wrap.appendChild(enrollBtn);
      if (u.role !== 'admin') wrap.appendChild(banBtn);
      tdActions.appendChild(wrap);

      tr.appendChild(tdUser);
      tr.appendChild(tdWm);
      tr.appendChild(tdDev);
      tr.appendChild(tdRisk);
      tr.appendChild(tdEnroll);
      tr.appendChild(tdActions);
      tbody.appendChild(tr);
    });
  }

  function renderCodesTable(codes) {
    const tbody = document.getElementById('admin-codes-tbody');
    tbody.innerHTML = '';

    codes.forEach((c) => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><span class="code-pill">${escapeHtml(c.code)}</span></td>
        <td>${c.used_by_user_id ? '<span class="badge badge-crimson">مُستخدم</span>' : '<span class="badge badge-emerald">متاح</span>'}</td>
        <td style="font-size:0.82rem;color:var(--text-muted);">${c.used_by_email ? escapeHtml(c.used_by_email) : '—'}</td>
      `;
      tbody.appendChild(tr);
    });
  }

  document.getElementById('generate-codes-btn')?.addEventListener('click', async () => {
    const res = await CourseSecurityClient.call('/api/admin/codes/generate', {
      method: 'POST',
      json: { count: 5 },
    });
    notify(`تم توليد 5 أكواد تفعيل جديدة: ${res.codes.join(' ، ')}`);
    await loadAdminData();
  });

  // ── Tab 2: Courses & Video Manager ───────────────────────────────
  function renderCourseManager(course) {
    if (!course) return;
    const modSelect = document.getElementById('vid-module');
    modSelect.innerHTML = '';
    course.modules.forEach((m) => {
      const opt = document.createElement('option');
      opt.value = String(m.id);
      opt.textContent = m.title;
      modSelect.appendChild(opt);
    });

    const list = document.getElementById('admin-lessons-list');
    list.innerHTML = '';
    course.videos.forEach((v) => {
      const box = document.createElement('div');
      box.style.cssText = 'padding:0.9rem;border:1px solid var(--border);border-radius:10px;background:var(--surface-2);';
      box.innerHTML = `
        <div style="display:flex;justify-content:space-between;align-items:center;gap:0.5rem;flex-wrap:wrap;margin-bottom:0.35rem;">
          <strong>${escapeHtml(v.title)}</strong>
          <span class="badge badge-wm">${escapeHtml(v.id)} • ${escapeHtml(v.duration)}</span>
        </div>
        <div style="font-size:0.8rem;color:var(--text-muted);word-break:break-all;margin-bottom:0.3rem;">
          رابط البث: <code>${escapeHtml(v.video_url)}</code>
        </div>
        <div style="font-size:0.78rem;color:var(--emerald);font-family:monospace;">
          AES-128 Key (16B): ${escapeHtml(v.aes_key_hex)}
        </div>
      `;
      list.appendChild(box);
    });
  }

  document.getElementById('add-module-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const input = document.getElementById('new-module-title');
    await CourseSecurityClient.call('/api/admin/courses/module', {
      method: 'POST',
      json: { title: input.value.trim() },
    });
    input.value = '';
    notify('تمت إضافة الوحدة التدريبية بنجاح.');
    await loadAdminData();
  });

  document.getElementById('save-video-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    await CourseSecurityClient.call('/api/admin/courses/video', {
      method: 'POST',
      json: {
        id: document.getElementById('vid-id').value.trim(),
        moduleId: Number(document.getElementById('vid-module').value),
        title: document.getElementById('vid-title').value.trim(),
        duration: document.getElementById('vid-duration').value.trim(),
        videoUrl: document.getElementById('vid-url').value.trim(),
        aesKeyHex: document.getElementById('vid-key').value.trim(),
        description: document.getElementById('vid-desc').value.trim(),
      },
    });
    document.getElementById('vid-id').value = '';
    document.getElementById('vid-title').value = '';
    document.getElementById('vid-desc').value = '';
    notify('تم حفظ الدرس وتوليد مفتاح التشفير AES-128 بنجاح.');
    await loadAdminData();
  });

  // ── Tab 3: Watermark Leak Lookup ─────────────────────────────────
  async function runLeakLookup(code) {
    const box = document.getElementById('leak-result-box');
    box.innerHTML = '';
    try {
      const res = await CourseSecurityClient.call(`/api/admin/leak-lookup?code=${encodeURIComponent(code)}`);
      const u = res.user;
      const card = document.createElement('div');
      card.style.cssText = 'padding:1.25rem;border:1px solid var(--crimson);border-radius:12px;background:var(--surface-2);';
      card.innerHTML = `
        <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:0.75rem;margin-bottom:0.9rem;">
          <div>
            <h3 style="font-size:1.2rem;">🎯 تم تحديد صاحب الكود المائي: ${escapeHtml(u.full_name)}</h3>
            <div style="color:var(--text-muted);font-size:0.9rem;">
              البريد: <strong>${escapeHtml(u.email)}</strong> • الهاتف/تيليجرام: <strong>${escapeHtml(u.phone || 'غير مسجل')}</strong>
            </div>
          </div>
          <span class="badge badge-wm" style="font-size:1rem;">${escapeHtml(u.watermark_code)}</span>
        </div>
        <div style="margin-bottom:0.9rem;">
          <strong>نقاط المخاطر الحالية (7 أيام):</strong> <span class="badge badge-crimson">${res.riskScore} نقطة</span>
          • <strong>الحالة:</strong> ${u.is_banned ? '<span class="badge badge-crimson">محظور</span>' : '<span class="badge badge-emerald">نشط</span>'}
        </div>
        <div style="margin-bottom:1rem;">
          <strong>الأجهزة المسجلة (${res.devices.length}):</strong>
          <ul style="margin-top:0.4rem;padding-right:1.2rem;font-size:0.88rem;color:var(--text-muted);">
            ${res.devices.map((d) => `<li>${escapeHtml(d.device_label)} — IP: <code>${escapeHtml(d.last_ip || 'N/A')}</code> (آخر نشاط: ${escapeHtml(d.last_seen_at)})</li>`).join('') || '<li>لا توجد أجهزة مسجلة</li>'}
          </ul>
        </div>
      `;

      const banBtn = document.createElement('button');
      banBtn.className = 'btn btn-primary';
      banBtn.textContent = u.is_banned ? '✓ الحساب محظور حالياً (اضغط لفك الحظر)' : '🚫 حظر الحساب فوراً وسحب جميع الجلسات';
      banBtn.addEventListener('click', async () => {
        await CourseSecurityClient.call(`/api/admin/users/${u.id}/ban`, {
          method: 'POST',
          json: { isBanned: !u.is_banned, reason: `تسريب فيديو يحمل الكود المائي ${u.watermark_code}` },
        });
        notify('تم تحديث حالة الحظر وسحب الجلسات فوراً.');
        await runLeakLookup(u.watermark_code);
        await loadAdminData();
      });

      card.appendChild(banBtn);
      box.appendChild(card);
    } catch (err) {
      box.innerHTML = `<div class="alert alert-error">${escapeHtml(err.message)}</div>`;
    }
  }

  document.getElementById('leak-search-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const code = document.getElementById('leak-code-input').value.trim();
    await runLeakLookup(code);
  });

  // ── Tab 4: Security Review Queue ─────────────────────────────────
  function renderSecurityQueue(users) {
    const container = document.getElementById('security-queue-list');
    container.innerHTML = '';

    const flagged = users.filter((u) => u.needs_review || u.requires_step_up || u.risk_score > 0);
    if (flagged.length === 0) {
      container.innerHTML = '<div style="color:var(--text-muted);">لا توجد حسابات في قائمة المراجعة الأمنية حالياً.</div>';
      return;
    }

    flagged.forEach((u) => {
      const box = document.createElement('div');
      box.style.cssText = 'padding:1.15rem;border:1px solid var(--border);border-radius:12px;background:var(--surface-2);';

      const eventsHtml = (u.events || []).slice(0, 6).map((ev) => `
        <div style="display:flex;justify-content:space-between;font-size:0.83rem;padding:0.3rem 0;border-bottom:1px dashed var(--border);">
          <span><code>${escapeHtml(ev.type)}</code> (+${ev.points} نقطة) — IP: <code>${escapeHtml(ev.ip || 'N/A')}</code></span>
          <span style="color:var(--text-muted);">${escapeHtml(ev.created_at)}</span>
        </div>
      `).join('');

      box.innerHTML = `
        <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:0.65rem;margin-bottom:0.75rem;">
          <div>
            <strong style="font-size:1.05rem;">${escapeHtml(u.full_name)}</strong>
            <span style="color:var(--text-muted);font-size:0.88rem;"> (${escapeHtml(u.email)})</span>
            <span class="badge badge-wm" style="margin-right:0.4rem;">${escapeHtml(u.watermark_code)}</span>
          </div>
          <div style="display:flex;gap:0.45rem;align-items:center;">
            <span class="badge ${u.risk_score >= 100 ? 'badge-crimson' : 'badge-amber'}">مجموع النقاط: ${u.risk_score}</span>
            ${u.requires_step_up ? '<span class="badge badge-amber">يتطلب Step-Up</span>' : ''}
            ${u.needs_review ? '<span class="badge badge-crimson">قيد المراجعة</span>' : ''}
          </div>
        </div>
        <div style="margin-bottom:0.85rem;">${eventsHtml}</div>
      `;

      const actions = document.createElement('div');
      actions.style.cssText = 'display:flex;gap:0.5rem;flex-wrap:wrap;';

      const clearBtn = document.createElement('button');
      clearBtn.className = 'btn btn-emerald btn-sm';
      clearBtn.textContent = '✓ تصفير نقاط المخاطر وإلغاء المراجعة';
      clearBtn.addEventListener('click', async () => {
        await CourseSecurityClient.call(`/api/admin/users/${u.id}/clear-risk`, { method: 'POST' });
        notify('تم تصفير نقاط المخاطر للحساب.');
        await loadAdminData();
      });

      const quotaBtn = document.createElement('button');
      quotaBtn.className = 'btn btn-outline btn-sm';
      quotaBtn.textContent = '🔄 إعادة تعيين حصة استبدال الأجهزة';
      quotaBtn.addEventListener('click', async () => {
        await CourseSecurityClient.call(`/api/admin/users/${u.id}/reset-quota`, { method: 'POST' });
        notify('تمت إعادة تعيين حصة استبدال الأجهزة الشهرية.');
        await loadAdminData();
      });

      const logoutAllBtn = document.createElement('button');
      logoutAllBtn.className = 'btn btn-outline btn-sm';
      logoutAllBtn.textContent = '🚪 تسجيل الخروج من كل الأجهزة';
      logoutAllBtn.addEventListener('click', async () => {
        await CourseSecurityClient.call(`/api/admin/users/${u.id}/logout-all`, { method: 'POST' });
        notify('تم إنهاء جميع الجلسات النشطة لهذا المشترك.');
        await loadAdminData();
      });

      const banBtn = document.createElement('button');
      banBtn.className = 'btn btn-primary btn-sm';
      banBtn.textContent = u.is_banned ? 'فك الحظر' : '🚫 حظر الحساب';
      banBtn.addEventListener('click', async () => {
        await CourseSecurityClient.call(`/api/admin/users/${u.id}/ban`, {
          method: 'POST',
          json: { isBanned: !u.is_banned, reason: 'تجاوز حد المخاطر الأمنية ومشاركة الحساب' },
        });
        notify('تم تحديث حالة الحظر.');
        await loadAdminData();
      });

      actions.appendChild(clearBtn);
      actions.appendChild(quotaBtn);
      actions.appendChild(logoutAllBtn);
      if (u.role !== 'admin') actions.appendChild(banBtn);
      box.appendChild(actions);
      container.appendChild(box);
    });
  }

  // ── Tab 5: Live OTP Log ──────────────────────────────────────────
  function renderOtpTable(logs) {
    const tbody = document.getElementById('admin-otp-tbody');
    tbody.innerHTML = '';

    if (!logs || logs.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-muted);">لا توجد أكواد تحقق صادرة بعد.</td></tr>';
      return;
    }

    logs.forEach((l) => {
      const tr = document.createElement('tr');
      const purposeText = l.purpose === 'new_device' ? 'ربط جهاز جديد' : 'تأكيد هوية (Step-Up)';
      const statusHtml = l.consumed_at
        ? '<span class="badge badge-muted">تم الاستخدام</span>'
        : '<span class="badge badge-emerald">نشط</span>';

      tr.innerHTML = `
        <td><strong>${escapeHtml(l.full_name)}</strong><br><span style="font-size:0.8rem;color:var(--text-muted);">${escapeHtml(l.email)}</span></td>
        <td>${purposeText}</td>
        <td><span class="code-pill" style="font-size:1.05rem;color:var(--crimson);">${escapeHtml(l.raw_code_preview || '******')}</span></td>
        <td>${l.attempts} / 5</td>
        <td>${statusHtml}</td>
        <td style="font-size:0.82rem;color:var(--text-muted);">${escapeHtml(l.created_at)}</td>
      `;
      tbody.appendChild(tr);
    });
  }

  function escapeHtml(str) {
    return String(str ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  document.getElementById('refresh-admin-btn')?.addEventListener('click', loadAdminData);
  document.getElementById('admin-logout-btn')?.addEventListener('click', async () => {
    await CourseSecurityClient.logout();
    location.href = '/';
  });

  await loadAdminData();
  await runLeakLookup('MZT-9912-Z');
});
