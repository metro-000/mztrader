document.addEventListener('DOMContentLoaded', async () => {
  'use strict';

  const stage = document.getElementById('player-stage');
  const video = document.getElementById('video');
  const banner = document.getElementById('portal-banner');
  const enrollmentGate = document.getElementById('enrollment-gate');
  const portalContent = document.getElementById('portal-content');

  let watermarkEl = document.getElementById('watermark');
  let watermarkText = '';
  let watermarkTimer = null;
  let watermarkObserver = null;
  let mutatingWatermark = false;
  let hls = null;
  let currentCourse = null;
  let currentLesson = null;

  video.addEventListener('contextmenu', (e) => e.preventDefault());

  function showBanner(msg, isSuccess = false) {
    banner.textContent = msg;
    banner.className = isSuccess ? 'alert alert-success' : 'alert alert-error';
    banner.hidden = false;
  }

  function hideBanner() {
    banner.hidden = true;
  }

  // ── 1. Moving Watermark + Loop-Safe DevTools Tamper Guard ────────
  function applyWatermarkStyle(el) {
    mutatingWatermark = true;
    try {
      const topPct = 10 + Math.floor(Math.random() * 72);  // 10% .. 81%
      const leftPct = 6 + Math.floor(Math.random() * 68);  // 6%  .. 73%
      el.textContent = watermarkText;
      el.setAttribute(
        'style',
        `position:absolute;top:${topPct}%;left:${leftPct}%;z-index:2147483647;` +
        'pointer-events:none;user-select:none;font:700 15px/1.3 monospace;direction:ltr;' +
        'color:rgba(255,255,255,0.45);text-shadow:0 1px 3px rgba(0,0,0,0.85);' +
        'background:rgba(11,14,20,0.28);padding:3px 8px;border-radius:4px;white-space:nowrap;' +
        'transition:top 0.45s ease,left 0.45s ease;'
      );
    } finally {
      mutatingWatermark = false;
    }
  }

  function ensureWatermarkIntact() {
    if (mutatingWatermark || !watermarkText) return;
    if (!watermarkEl || !stage.contains(watermarkEl)) {
      mutatingWatermark = true;
      try {
        watermarkEl = document.createElement('div');
        watermarkEl.id = 'watermark';
        watermarkEl.setAttribute('aria-hidden', 'true');
        stage.appendChild(watermarkEl);
      } finally {
        mutatingWatermark = false;
      }
      applyWatermarkStyle(watermarkEl);
      return;
    }
    const cs = window.getComputedStyle(watermarkEl);
    if (
      cs.display === 'none' ||
      cs.visibility === 'hidden' ||
      Number(cs.opacity) < 0.2 ||
      watermarkEl.textContent !== watermarkText
    ) {
      applyWatermarkStyle(watermarkEl);
    }
  }

  function startWatermark(text) {
    watermarkText = text;
    applyWatermarkStyle(watermarkEl);
    clearInterval(watermarkTimer);
    watermarkTimer = setInterval(() => {
      ensureWatermarkIntact();
      applyWatermarkStyle(watermarkEl);
    }, 5000);

    if (!watermarkObserver) {
      watermarkObserver = new MutationObserver(() => ensureWatermarkIntact());
      watermarkObserver.observe(stage, {
        childList: true,
        subtree: true,
        attributes: true,
        characterData: true,
      });
    }
  }

  // Keep fullscreen on #player-stage so the watermark overlay stays visible in fullscreen
  document.addEventListener('fullscreenchange', () => {
    if (document.fullscreenElement === video && stage.requestFullscreen) {
      document.exitFullscreen().then(() => stage.requestFullscreen()).catch(() => {});
    }
  });

  document.getElementById('stage-fullscreen-btn')?.addEventListener('click', () => {
    if (document.fullscreenElement) {
      document.exitFullscreen().catch(() => {});
    } else if (stage.requestFullscreen) {
      stage.requestFullscreen().catch(() => {});
    }
  });

  document.getElementById('speed-select')?.addEventListener('change', (e) => {
    video.playbackRate = Number(e.target.value) || 1;
  });

  // ── 2. Protected AES-128 HLS Playback ────────────────────────────
  function stopPlayback(msg) {
    CourseSecurityClient.onPaused();
    video.pause();
    if (hls) {
      hls.stopLoad();
      hls.detachMedia();
    } else {
      video.removeAttribute('src');
      video.load();
    }
    clearInterval(watermarkTimer);
    if (msg) showBanner(msg);
  }

  async function playLesson(lesson) {
    currentLesson = lesson;
    hideBanner();
    stage.dataset.videoId = lesson.id;

    document.getElementById('lesson-title').textContent = lesson.title;
    document.getElementById('lesson-duration').textContent = `⏱️ مدة الدرس: ${lesson.duration}`;
    document.getElementById('lesson-description').textContent = lesson.description;

    const attachBtn = document.getElementById('lesson-attachment-btn');
    if (lesson.attachment_url) {
      attachBtn.href = lesson.attachment_url;
      attachBtn.hidden = false;
    } else {
      attachBtn.hidden = true;
    }

    updateMarkCompleteButton(lesson.completed);
    highlightActiveLesson(lesson.id);

    try {
      const { manifestUrl, watermark } = await CourseSecurityClient.startLesson(lesson.id);
      startWatermark(watermark);

      if (hls) {
        hls.destroy();
        hls = null;
      }

      if (window.Hls && window.Hls.isSupported()) {
        hls = new window.Hls({
          xhrSetup(xhr) {
            xhr.withCredentials = true;
          },
        });
        hls.loadSource(manifestUrl);
        hls.attachMedia(video);

        hls.on(window.Hls.Events.ERROR, (_event, data) => {
          const status = data?.response?.code;
          if (status === 409) {
            stopPlayback('تم إيقاف البث لأن حسابك بدأ المشاهدة على جهاز آخر.');
          } else if (status === 403) {
            stopPlayback('مطلوب تأكيد الهوية الأمنية للمتابعة.');
            openStepUpModal();
          } else if (status === 401) {
            location.href = '/';
          }
        });
      } else if (video.canPlayType('application/vnd.apple.mpegurl')) {
        video.src = manifestUrl;
      } else {
        showBanner('متصفحك لا يدعم تشغيل البث المشفر HLS.');
      }
    } catch (err) {
      if (err.code === 'STEP_UP_REQUIRED') {
        openStepUpModal();
        return;
      }
      showBanner(err.message);
    }
  }

  video.addEventListener('play', CourseSecurityClient.onPlaying);
  video.addEventListener('pause', CourseSecurityClient.onPaused);
  video.addEventListener('ended', CourseSecurityClient.onPaused);

  document.addEventListener('course:stream-conflict', () => {
    stopPlayback('تم إيقاف البث لأن حسابك بدأ المشاهدة على جهاز آخر.');
  });

  document.addEventListener('course:step-up-required', () => {
    stopPlayback('يرجى تأكيد هويتك بكود التحقق لمتابعة المشاهدة.');
    openStepUpModal();
  });

  document.addEventListener('course:session-expired', () => {
    location.href = '/';
  });

  // ── 3. Curriculum & Progress UI ──────────────────────────────────
  function renderCurriculum(course) {
    currentCourse = course;
    document.getElementById('course-title').textContent = course.title;
    updateProgressHeader(course.completedCount, course.totalLessons);

    const list = document.getElementById('curriculum-list');
    list.innerHTML = '';

    course.modules.forEach((mod) => {
      const card = document.createElement('div');
      card.className = 'module-card';

      const header = document.createElement('div');
      header.className = 'module-header';
      header.textContent = mod.title;
      card.appendChild(header);

      mod.lessons.forEach((lesson) => {
        const item = document.createElement('div');
        item.className = 'lesson-item';
        item.dataset.lessonId = lesson.id;

        const left = document.createElement('div');
        left.style.cssText = 'display:flex;align-items:center;gap:0.55rem;';

        const statusBadge = document.createElement('span');
        statusBadge.className = lesson.completed ? 'badge badge-emerald' : 'badge badge-wm';
        statusBadge.textContent = lesson.completed ? '✓' : '▶';

        const titleSpan = document.createElement('span');
        titleSpan.style.fontWeight = '600';
        titleSpan.style.fontSize = '0.9rem';
        titleSpan.textContent = lesson.title;

        left.appendChild(statusBadge);
        left.appendChild(titleSpan);

        const dur = document.createElement('span');
        dur.style.cssText = 'font-size:0.8rem;color:var(--text-muted);white-space:nowrap;';
        dur.textContent = lesson.duration;

        item.appendChild(left);
        item.appendChild(dur);

        item.addEventListener('click', () => playLesson(lesson));
        card.appendChild(item);
      });

      list.appendChild(card);
    });
  }

  function updateProgressHeader(completed, total) {
    document.getElementById('course-progress-text').textContent = `${completed} / ${total} دروس مكتملة`;
    const pct = total > 0 ? Math.round((completed / total) * 100) : 0;
    document.getElementById('course-progress-bar').style.width = `${pct}%`;
  }

  function highlightActiveLesson(lessonId) {
    document.querySelectorAll('.lesson-item').forEach((el) => {
      el.classList.toggle('active', el.dataset.lessonId === lessonId);
    });
  }

  function updateMarkCompleteButton(isCompleted) {
    const btn = document.getElementById('mark-complete-btn');
    if (isCompleted) {
      btn.textContent = '✓ مكتمل (اضغط لإلغاء الاكتمال)';
      btn.className = 'btn btn-outline btn-sm';
    } else {
      btn.textContent = '✓ تحديد كمكتمل';
      btn.className = 'btn btn-emerald btn-sm';
    }
  }

  document.getElementById('mark-complete-btn')?.addEventListener('click', async () => {
    if (!currentLesson) return;
    try {
      const nextState = !currentLesson.completed;
      const res = await CourseSecurityClient.call(
        `/api/lessons/${encodeURIComponent(currentLesson.id)}/complete`,
        { method: 'POST', json: { completed: nextState } }
      );
      currentLesson.completed = nextState;
      updateMarkCompleteButton(nextState);
      updateProgressHeader(res.completedCount, res.totalLessons);
      renderCurriculum(currentCourse);
      highlightActiveLesson(currentLesson.id);
    } catch (err) {
      showBanner(err.message);
    }
  });

  // ── 4. Activation Code Gate ──────────────────────────────────────
  document.getElementById('activate-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const alertBox = document.getElementById('activate-alert');
    alertBox.hidden = true;
    try {
      const code = document.getElementById('activate-code-input').value.trim();
      await CourseSecurityClient.call('/api/enroll/activate', {
        method: 'POST',
        json: { code },
      });
      await loadPortalOverview();
    } catch (err) {
      alertBox.textContent = err.message;
      alertBox.hidden = false;
    }
  });

  // ── 5. My Registered Devices Modal ───────────────────────────────
  const devicesModal = document.getElementById('devices-modal');
  const devicesModalError = document.getElementById('devices-modal-error');

  async function openDevicesModal() {
    devicesModalError.hidden = true;
    devicesModal.hidden = false;
    try {
      const data = await CourseSecurityClient.listDevices();
      document.getElementById('modal-changes-left').textContent = String(data.changesLeft ?? 0);
      const container = document.getElementById('devices-list-container');
      container.innerHTML = '';

      data.devices.forEach((d) => {
        const row = document.createElement('div');
        row.style.cssText = 'display:flex;justify-content:space-between;align-items:center;padding:0.85rem;border:1px solid var(--border);border-radius:10px;background:var(--surface-2);gap:0.75rem;flex-wrap:wrap;';

        const info = document.createElement('div');
        const title = document.createElement('div');
        title.style.fontWeight = '700';
        title.textContent = d.label + (d.current ? ' ' : '');
        if (d.current) {
          const curBadge = document.createElement('span');
          curBadge.className = 'badge badge-emerald';
          curBadge.style.marginRight = '0.4rem';
          curBadge.textContent = 'الجهاز الحالي';
          title.appendChild(curBadge);
        }

        const sub = document.createElement('div');
        sub.style.cssText = 'font-size:0.8rem;color:var(--text-muted);';
        sub.textContent = `آخر نشاط: ${d.lastSeenAt || 'الآن'} ${d.ip ? `• IP: ${d.ip}` : ''}`;

        info.appendChild(title);
        info.appendChild(sub);

        const removeBtn = document.createElement('button');
        removeBtn.type = 'button';
        removeBtn.className = 'btn btn-outline btn-sm';
        removeBtn.textContent = 'إزالة الجهاز';
        removeBtn.addEventListener('click', async () => {
          try {
            await CourseSecurityClient.removeDevice(d.id);
            if (d.current) {
              location.href = '/';
              return;
            }
            await openDevicesModal();
          } catch (err) {
            devicesModalError.textContent = err.message;
            devicesModalError.hidden = false;
          }
        });

        row.appendChild(info);
        row.appendChild(removeBtn);
        container.appendChild(row);
      });
    } catch (err) {
      devicesModalError.textContent = err.message;
      devicesModalError.hidden = false;
    }
  }

  document.getElementById('open-devices-btn')?.addEventListener('click', openDevicesModal);
  document.getElementById('close-devices-modal')?.addEventListener('click', () => {
    devicesModal.hidden = true;
  });

  // ── 6. Step-Up Verification Modal ────────────────────────────────
  const stepUpModal = document.getElementById('step-up-modal');
  const stepUpDevHint = document.getElementById('step-up-dev-hint');
  const stepUpError = document.getElementById('step-up-error');
  const stepUpCodeInput = document.getElementById('step-up-code-input');

  async function openStepUpModal() {
    stepUpError.hidden = true;
    stepUpModal.hidden = false;
    try {
      const res = await CourseSecurityClient.startStepUp();
      if (res.devCodeHint) {
        stepUpDevHint.textContent = `وضع الاختبار المجاني — كود تأكيد الهوية المباشر هو: ${res.devCodeHint}`;
        stepUpDevHint.hidden = false;
        stepUpCodeInput.value = res.devCodeHint;
      } else {
        stepUpDevHint.hidden = true;
      }
    } catch (err) {
      stepUpError.textContent = err.message;
      stepUpError.hidden = false;
    }
  }

  document.getElementById('resend-step-up-btn')?.addEventListener('click', openStepUpModal);

  document.getElementById('step-up-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    stepUpError.hidden = true;
    try {
      await CourseSecurityClient.verifyStepUp(stepUpCodeInput.value.trim());
      stepUpModal.hidden = true;
      hideBanner();
      await loadPortalOverview();
    } catch (err) {
      stepUpError.textContent = err.message;
      stepUpError.hidden = false;
    }
  });

  // ── 7. Logout & Initial Load ─────────────────────────────────────
  document.getElementById('logout-btn')?.addEventListener('click', async () => {
    await CourseSecurityClient.logout();
    location.href = '/';
  });

  async function loadPortalOverview() {
    try {
      const data = await CourseSecurityClient.call('/api/portal/overview');
      document.getElementById('nav-user-name').textContent = data.user.fullName;
      document.getElementById('nav-watermark-badge').textContent = `ID: ${data.user.watermarkCode}`;
      document.getElementById('open-devices-btn').textContent = `💻 أجهزتي (${data.devices.length}/2)`;

      if (data.user.role === 'admin') {
        document.getElementById('nav-admin-link').hidden = false;
      }

      if (data.user.requiresStepUp && data.user.role !== 'admin') {
        await openStepUpModal();
        return;
      }

      if (!data.user.isEnrolled) {
        enrollmentGate.hidden = false;
        portalContent.hidden = true;
        return;
      }

      enrollmentGate.hidden = true;
      portalContent.hidden = false;

      if (data.course) {
        renderCurriculum(data.course);
        const firstLesson = data.course.modules[0]?.lessons[0];
        if (firstLesson) {
          await playLesson(firstLesson);
        }
      }
    } catch {
      location.href = '/';
    }
  }

  await loadPortalOverview();
});
