/*
 * main.c - Ciphers GTK3 GUI.
 *
 * A small front-end over the cipher engine in crypto.c. The actual
 * encryption/decryption runs on a worker thread so the 1 GiB+ Argon2id
 * KDF does not freeze the UI.
 */
#include <gtk/gtk.h>
#include <string.h>
#include <sodium.h>
#include "crypto.h"
#include "secure_buffer.h"

#ifndef CIPHERS_VERSION
#define CIPHERS_VERSION "1.0.2"
#endif
#define APP_ID "org.ciphers.Ciphers"

/* Cyber-styled dark theme. Applied app-wide via a CSS provider. */
static const char *APP_CSS =
    "window, .ciphers-root {"
    "  background-color: #070b12;"
    "  color: #c8f7ff;"
    "}"
    "headerbar, .titlebar {"
    "  background: linear-gradient(90deg, #0a0f1a, #0e1726, #0a0f1a);"
    "  border-bottom: 1px solid #00e5ff;"
    "  box-shadow: 0 1px 8px rgba(0,229,255,0.35);"
    "  min-height: 40px;"
    "}"
    "headerbar .title {"
    "  color: #00e5ff;"
    "  font-family: monospace;"
    "  font-weight: bold;"
    "  letter-spacing: 3px;"
    "}"
    "headerbar .subtitle { color: #3d7d8f; font-family: monospace; }"
    ".hb-title {"
    "  color: #00e5ff; font-family: monospace; font-weight: bold;"
    "  letter-spacing: 2px;"
    "}"
    /* Keep title-bar buttons small so they never crowd the title. */
    "headerbar button {"
    "  padding: 2px 10px; margin: 4px 2px; min-height: 0; min-width: 0;"
    "  letter-spacing: 0;"
    "}"
    "headerbar button.titlebutton {"
    "  padding: 2px; margin: 2px; min-height: 22px; min-width: 22px;"
    "}"
    "label { color: #9fd6e6; font-family: monospace; }"
    ".field-label { color: #5fb4c9; letter-spacing: 1px; }"
    ".brand {"
    "  color: #00e5ff; font-family: monospace; font-weight: bold;"
    "  font-size: 22px; letter-spacing: 6px;"
    "}"
    ".subtitle { color: #3d7d8f; font-size: 10px; letter-spacing: 4px; }"
    "entry {"
    "  background-color: #0c1421; color: #d8feff;"
    "  border: 1px solid #14384a;"
    "  border-radius: 4px; padding: 7px; font-family: monospace;"
    "  caret-color: #00e5ff;"
    "}"
    "entry:focus {"
    "  border-color: #00e5ff;"
    "  box-shadow: 0 0 6px rgba(0,229,255,0.6);"
    "}"
    "combobox box, combobox button, combobox {"
    "  background-color: #0c1421; color: #d8feff;"
    "  border: 1px solid #14384a; border-radius: 4px;"
    "  font-family: monospace;"
    "}"
    "combobox button:hover { border-color: #00e5ff; }"
    "radiobutton, checkbutton { color: #9fd6e6; font-family: monospace; }"
    "radiobutton check, checkbutton check {"
    "  background-color: #0c1421; border: 1px solid #2a6b80;"
    "}"
    "radiobutton check:checked, checkbutton check:checked {"
    "  background-color: #00e5ff; border-color: #00e5ff;"
    "}"
    "button {"
    "  background: #0e1b2b; color: #9fe9ff;"
    "  border: 1px solid #1d4c5e; border-radius: 4px;"
    "  padding: 7px 14px; font-family: monospace; letter-spacing: 1px;"
    "}"
    "button:hover {"
    "  border-color: #00e5ff; color: #ffffff;"
    "  box-shadow: 0 0 8px rgba(0,229,255,0.45);"
    "}"
    "button:active { background: #102a3a; }"
    "button:disabled { color: #3a566a; border-color: #16313e; }"
    ".action-button {"
    "  background: linear-gradient(90deg, #00b3c4, #00e5ff);"
    "  color: #02121a; font-weight: bold; letter-spacing: 2px;"
    "  border: 1px solid #00e5ff;"
    "}"
    ".action-button:hover {"
    "  box-shadow: 0 0 14px rgba(0,229,255,0.8);"
    "  color: #000000;"
    "}"
    "progressbar text { color: #9fe9ff; font-family: monospace; font-size: 10px; }"
    "progressbar trough {"
    "  background-color: #0c1421; border: 1px solid #14384a;"
    "  border-radius: 4px; min-height: 18px;"
    "}"
    "progressbar progress {"
    "  background: linear-gradient(90deg, #00b3c4, #39ff14);"
    "  border-radius: 4px; min-height: 18px;"
    "  box-shadow: 0 0 10px rgba(57,255,20,0.6);"
    "}"
    ".status-ok { color: #39ff14; }"
    ".status-err { color: #ff426f; }"
    ".status-run { color: #00e5ff; }";

#define PASSWORD_MAX 4096

typedef struct Job Job;

typedef struct {
    GtkApplication *gapp;
    GtkWidget *window;
    GtkWidget *radio_encrypt;
    GtkWidget *radio_decrypt;
    GtkWidget *in_entry;
    GtkWidget *out_entry;
    GtkWidget *cipher_combo;
    GtkWidget *kdf_combo;
    GtkWidget *hybrid_check;
    GtkWidget *pass_entry;
    GtkWidget *reveal_check;
    GtkWidget *run_button;
    GtkWidget *progress;
    GtkWidget *status;
    guint      pulse_id;        /* KDF "deriving key" pulse timer, 0 if none */
    gboolean   pulsing;
    volatile int window_gone;   /* set when the window is destroyed */
    Job * volatile current_job; /* in-flight job, or NULL */
} App;

/* Shared between worker thread and main loop. */
struct Job {
    App        *app;
    char        in_path[4096];
    char        out_path[4096];
    char        password[PASSWORD_MAX];
    cipher_id_t cipher;
    kdf_level_t level;
    int         hybrid;
    int         decrypt;
    /* results */
    int         rc;
    char        err[256];
    /* progress (written by worker, read on main loop). Guarded by plock so
     * the 64-bit/double reads can't tear against the worker's writes. */
    GMutex            plock;
    double            fraction;
    uint64_t          done_bytes;
    uint64_t          total_bytes;
    volatile int      cancelled;
    /* 1 while a progress idle is already queued; coalesces the per-chunk
     * callbacks so we never flood the main loop with thousands of sources. */
    volatile gint     idle_queued;
};

/* ----- progress plumbing ----------------------------------------------- */

static void human_size(uint64_t b, char *out, size_t n) {
    const char *u[] = { "B", "KB", "MB", "GB", "TB" };
    double v = (double)b; int i = 0;
    while (v >= 1024.0 && i < 4) { v /= 1024.0; i++; }
    snprintf(out, n, i == 0 ? "%.0f %s" : "%.1f %s", v, u[i]);
}

static gboolean update_progress_idle(gpointer data) {
    Job *job = data;
    App *app = job->app;
    /* Allow the next burst of progress callbacks to queue a fresh idle. */
    g_atomic_int_set(&job->idle_queued, 0);
    if (app->window_gone) return G_SOURCE_REMOVE;   /* widgets are gone */
    app->pulsing = FALSE;                            /* real progress now */
    GtkProgressBar *pb = GTK_PROGRESS_BAR(app->progress);
    g_mutex_lock(&job->plock);
    double   fraction = job->fraction;
    uint64_t done = job->done_bytes, tot = job->total_bytes;
    g_mutex_unlock(&job->plock);
    gtk_progress_bar_set_fraction(pb, fraction);
    char d[32], t[32], txt[96];
    human_size(done, d, sizeof d);
    human_size(tot, t, sizeof t);
    if (tot)
        snprintf(txt, sizeof txt, "%.0f%%   %s / %s", fraction * 100.0, d, t);
    else
        snprintf(txt, sizeof txt, "%s", d);
    gtk_progress_bar_set_text(pb, txt);
    return G_SOURCE_REMOVE;
}

static int progress_cb(uint64_t done, uint64_t total, void *user) {
    Job *job = user;
    g_mutex_lock(&job->plock);
    job->done_bytes = done;
    job->total_bytes = total;
    job->fraction = total ? (double)done / (double)total : 0.0;
    g_mutex_unlock(&job->plock);
    /* Coalesce: only schedule an update if one isn't already pending. The
     * idle handler always reads the latest values above, so dropping
     * intermediate notifications loses nothing but the redundant redraws. */
    if (g_atomic_int_compare_and_exchange(&job->idle_queued, 0, 1))
        g_idle_add(update_progress_idle, job);
    return job->cancelled;
}

/* ----- worker thread ---------------------------------------------------- */

/* Swap the single status-* style class on the status label. */
static void set_status(App *app, const char *cls, const char *text) {
    GtkStyleContext *sc = gtk_widget_get_style_context(app->status);
    gtk_style_context_remove_class(sc, "status-ok");
    gtk_style_context_remove_class(sc, "status-err");
    gtk_style_context_remove_class(sc, "status-run");
    if (cls) gtk_style_context_add_class(sc, cls);
    gtk_label_set_text(GTK_LABEL(app->status), text);
}

/* Free the App container itself. Widgets are owned by GTK; this only
 * releases the heap struct allocated in activate(). Must run after the
 * window is gone and no job is in flight (nothing else references app). */
static void free_app(App *app) {
    g_free(app);
}

static gboolean job_finished_idle(gpointer data) {
    Job *job = data;
    App *app = job->app;

    app->current_job = NULL;
    app->pulsing = FALSE;

    /* The window was closed while we were working: don't touch destroyed
     * widgets, just clean up and let the held application quit. This idle
     * runs after every pending progress idle (FIFO, same priority), so no
     * source still references app once we free it here. */
    if (app->window_gone) {
        sodium_munlock(job->password, sizeof(job->password));
        g_mutex_clear(&job->plock);
        g_free(job);
        g_application_release(G_APPLICATION(app->gapp));
        free_app(app);
        return G_SOURCE_REMOVE;
    }

    gtk_widget_set_sensitive(app->run_button, TRUE);
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(app->progress),
                                  job->rc == 0 ? 1.0 : 0.0);

    if (job->rc == 0) {
        gchar *msg = g_strdup_printf("\xE2\x9C\x94 %s written to:\n%s",
                                     job->decrypt ? "Decrypted file" : "Encrypted file",
                                     job->out_path);
        set_status(app, "status-ok", msg);
        g_free(msg);
    } else {
        gchar *msg = g_strdup_printf("\xE2\x9C\x96 %s", job->err);
        set_status(app, "status-err", msg);
        GtkWidget *d = gtk_message_dialog_new(GTK_WINDOW(app->window),
            GTK_DIALOG_MODAL, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK,
            "%s", job->err);
        gtk_dialog_run(GTK_DIALOG(d));
        gtk_widget_destroy(d);
    }

    /* Scrub the password copy. */
    sodium_munlock(job->password, sizeof(job->password));
    g_mutex_clear(&job->plock);
    g_free(job);
    g_application_release(G_APPLICATION(app->gapp));
    return G_SOURCE_REMOVE;
}

/* Pulse the progress bar while the (potentially slow) KDF runs, before any
 * byte-level progress is available. Removes itself once pulsing stops. */
static gboolean pulse_cb(gpointer data) {
    App *app = data;
    if (!app->pulsing || app->window_gone) { app->pulse_id = 0; return G_SOURCE_REMOVE; }
    gtk_progress_bar_pulse(GTK_PROGRESS_BAR(app->progress));
    return G_SOURCE_CONTINUE;
}

static gpointer worker_thread(gpointer data) {
    Job *job = data;
    if (job->decrypt) {
        job->rc = ciphers_decrypt_file(job->in_path, job->out_path, job->password,
                                       progress_cb, job, job->err, sizeof(job->err));
    } else {
        job->rc = ciphers_encrypt_file(job->in_path, job->out_path, job->password,
                                       job->cipher, job->level, job->hybrid,
                                       progress_cb, job, job->err, sizeof(job->err));
    }
    g_idle_add(job_finished_idle, job);
    return NULL;
}

/* ----- UI callbacks ----------------------------------------------------- */

static void on_reveal_toggled(GtkToggleButton *btn, gpointer user) {
    App *app = user;
    gtk_entry_set_visibility(GTK_ENTRY(app->pass_entry),
                             gtk_toggle_button_get_active(btn));
}

static void browse_file(App *app, GtkWidget *entry, gboolean save) {
    GtkWidget *dlg = gtk_file_chooser_dialog_new(
        save ? "Select output file" : "Select input file",
        GTK_WINDOW(app->window),
        save ? GTK_FILE_CHOOSER_ACTION_SAVE : GTK_FILE_CHOOSER_ACTION_OPEN,
        "_Cancel", GTK_RESPONSE_CANCEL,
        save ? "_Save" : "_Open", GTK_RESPONSE_ACCEPT, NULL);
    if (save)
        gtk_file_chooser_set_do_overwrite_confirmation(GTK_FILE_CHOOSER(dlg), TRUE);
    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_ACCEPT) {
        char *f = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dlg));
        gtk_entry_set_text(GTK_ENTRY(entry), f);
        g_free(f);
    }
    gtk_widget_destroy(dlg);
}

static void on_browse_in(GtkButton *b, gpointer user) {
    (void)b; App *app = user; browse_file(app, app->in_entry, FALSE);
}
static void on_browse_out(GtkButton *b, gpointer user) {
    (void)b; App *app = user; browse_file(app, app->out_entry, TRUE);
}

static void on_mode_toggled(GtkToggleButton *btn, gpointer user) {
    (void)btn;
    App *app = user;
    gboolean enc = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(app->radio_encrypt));
    /* Cipher and KDF choices only apply to encryption; on decrypt they are
     * read from the file header. */
    gtk_widget_set_sensitive(app->cipher_combo, enc);
    gtk_widget_set_sensitive(app->kdf_combo, enc);
    /* Hybrid mode is an encrypt-time choice; on decrypt it is auto-detected
     * from the file header. */
    gtk_widget_set_sensitive(app->hybrid_check, enc);
    gtk_button_set_label(GTK_BUTTON(app->run_button), enc ? "ENCRYPT" : "DECRYPT");
}

static void on_run(GtkButton *b, gpointer user) {
    (void)b;
    App *app = user;
    const char *in  = gtk_entry_get_text(GTK_ENTRY(app->in_entry));
    const char *out = gtk_entry_get_text(GTK_ENTRY(app->out_entry));
    const char *pw  = gtk_entry_get_text(GTK_ENTRY(app->pass_entry));
    gboolean enc = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(app->radio_encrypt));

    if (!in || !*in || !out || !*out || !pw || !*pw) {
        GtkWidget *d = gtk_message_dialog_new(GTK_WINDOW(app->window),
            GTK_DIALOG_MODAL, GTK_MESSAGE_WARNING, GTK_BUTTONS_OK,
            "Please fill in the input file, output file and password.");
        gtk_dialog_run(GTK_DIALOG(d));
        gtk_widget_destroy(d);
        return;
    }
    if (strlen(pw) >= PASSWORD_MAX) {
        GtkWidget *d = gtk_message_dialog_new(GTK_WINDOW(app->window),
            GTK_DIALOG_MODAL, GTK_MESSAGE_WARNING, GTK_BUTTONS_OK,
            "Password is too long (maximum %d characters).", PASSWORD_MAX - 1);
        gtk_dialog_run(GTK_DIALOG(d));
        gtk_widget_destroy(d);
        return;
    }

    Job *job = g_new0(Job, 1);
    g_mutex_init(&job->plock);
    /* Pin the password copy in RAM (no swap, non-dumpable). munlock at the
     * free sites zeroes it. */
    sodium_mlock(job->password, sizeof(job->password));
    job->app = app;
    job->decrypt = enc ? 0 : 1;
    g_strlcpy(job->in_path, in, sizeof(job->in_path));
    g_strlcpy(job->out_path, out, sizeof(job->out_path));
    g_strlcpy(job->password, pw, sizeof(job->password));

    /* cipher_combo id strings are the numeric cipher ids. */
    const gchar *cid = gtk_combo_box_get_active_id(GTK_COMBO_BOX(app->cipher_combo));
    job->cipher = cid ? (cipher_id_t)atoi(cid) : CIPHER_AES_256_GCM;
    const gchar *kid = gtk_combo_box_get_active_id(GTK_COMBO_BOX(app->kdf_combo));
    job->level = kid ? (kdf_level_t)atoi(kid) : KDF_MEDIUM;
    job->hybrid = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(app->hybrid_check)) ? 1 : 0;

    gtk_widget_set_sensitive(app->run_button, FALSE);
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(app->progress), 0.0);
    gtk_progress_bar_set_text(GTK_PROGRESS_BAR(app->progress), "deriving key\xE2\x80\xA6");
    set_status(app, "status-run",
               enc ? "\xE2\x96\xB6 Encrypting\xE2\x80\xA6 (deriving key, this may take a moment)"
                   : "\xE2\x96\xB6 Decrypting\xE2\x80\xA6 (deriving key, this may take a moment)");

    /* Animate the bar during key derivation (no byte progress yet). */
    app->pulsing = TRUE;
    if (app->pulse_id == 0)
        app->pulse_id = g_timeout_add(110, pulse_cb, app);

    /* Keep the application (and main loop) alive until the worker finishes,
     * even if the user closes the window mid-operation. */
    app->current_job = job;
    g_application_hold(G_APPLICATION(app->gapp));

    GError *gerr = NULL;
    GThread *t = g_thread_try_new("ciphers-worker", worker_thread, job, &gerr);
    if (!t) {
        g_application_release(G_APPLICATION(app->gapp));
        app->current_job = NULL;
        app->pulsing = FALSE;
        gtk_widget_set_sensitive(app->run_button, TRUE);
        set_status(app, "status-err", "\xE2\x9C\x96 Could not start worker thread.");
        sodium_munlock(job->password, sizeof(job->password));
        g_mutex_clear(&job->plock);
        g_free(job);
        if (gerr) g_error_free(gerr);
        return;
    }
    g_thread_unref(t);
}

static void on_about(GtkButton *b, gpointer user) {
    (void)b;
    App *app = user;
    const gchar *authors[] = { "Jean-Francois Lachance-Caumartin", NULL };
    const gchar *features =
        "Ciphers is a simple, secure file encryption tool.\n\n"
        "Features:\n"
        "• Encrypt and decrypt any file with a password\n"
        "• AES-256-GCM (default), XChaCha20-Poly1305 or\n"
        "  ChaCha20-Poly1305 authenticated encryption\n"
        "• Optional post-quantum hybrid KEM (Kyber-1024 + X448):\n"
        "  the AEAD key comes from a hybrid key encapsulation whose\n"
        "  secret key is wrapped by your password\n"
        "• Argon2id key derivation, configurable strength:\n"
        "    – Basic (256 MiB)\n"
        "    – Medium (1 GiB, parallel) — minimum recommended\n"
        "    – Strong (4 GiB, parallel)\n"
        "• Chunked streaming with per-chunk authentication\n"
        "  (tamper, reorder and truncation detection)\n"
        "• Hardened memory: passwords, keys and plaintext are kept\n"
        "  in locked, non-dumpable memory and never hit swap\n"
        "• Optional password reveal for long passphrases";

    GtkWidget *d = gtk_about_dialog_new();
    GtkAboutDialog *ad = GTK_ABOUT_DIALOG(d);
    gtk_about_dialog_set_program_name(ad, "Ciphers");
    gtk_about_dialog_set_version(ad, CIPHERS_VERSION);
    gtk_about_dialog_set_comments(ad, features);
    gtk_about_dialog_set_authors(ad, authors);
    gtk_about_dialog_set_copyright(ad, "© 2026 Jean-Francois Lachance-Caumartin");
    gtk_about_dialog_set_license_type(ad, GTK_LICENSE_MIT_X11);
    gtk_about_dialog_set_logo_icon_name(ad, "ciphers");
    gtk_window_set_transient_for(GTK_WINDOW(d), GTK_WINDOW(app->window));
    gtk_dialog_run(GTK_DIALOG(d));
    gtk_widget_destroy(d);
}

/* ----- layout helpers --------------------------------------------------- */

static GtkWidget *labeled_row(const char *text, GtkWidget *widget, GtkWidget *extra) {
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    GtkWidget *lbl = gtk_label_new(text);
    gtk_widget_set_size_request(lbl, 120, -1);
    gtk_label_set_xalign(GTK_LABEL(lbl), 0.0);
    gtk_style_context_add_class(gtk_widget_get_style_context(lbl), "field-label");
    gtk_box_pack_start(GTK_BOX(box), lbl, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), widget, TRUE, TRUE, 0);
    if (extra) gtk_box_pack_start(GTK_BOX(box), extra, FALSE, FALSE, 0);
    return box;
}

/* Window is being destroyed: mark it gone and ask any in-flight job to
 * abort. The application hold (taken in on_run) keeps the main loop alive
 * until the worker's completion callback runs and releases it. */
static void on_window_destroy(GtkWidget *w, gpointer user) {
    (void)w;
    App *app = user;
    app->window_gone = 1;
    Job *job = app->current_job;
    if (job) {
        /* A worker is still running; it owns app's lifetime now and will free
         * it from job_finished_idle once it observes the cancellation. */
        job->cancelled = 1;
    } else {
        /* No job in flight: nothing else references app, so free it here. */
        free_app(app);
    }
}

/* Load the app-wide CSS theme once for the default screen. */
static void load_css(void) {
    GtkCssProvider *p = gtk_css_provider_new();
    gtk_css_provider_load_from_data(p, APP_CSS, -1, NULL);
    gtk_style_context_add_provider_for_screen(
        gdk_screen_get_default(), GTK_STYLE_PROVIDER(p),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(p);
}

static void activate(GtkApplication *gapp, gpointer user) {
    (void)user;
    App *app = g_new0(App, 1);
    app->gapp = gapp;

    load_css();

    app->window = gtk_application_window_new(gapp);
    gtk_window_set_title(GTK_WINDOW(app->window), "Ciphers");
    gtk_window_set_default_size(GTK_WINDOW(app->window), 580, -1);
    gtk_window_set_icon_name(GTK_WINDOW(app->window), "ciphers");
    /* Start centered horizontally (and vertically) on the screen. */
    gtk_window_set_position(GTK_WINDOW(app->window), GTK_WIN_POS_CENTER);

    /* Cyber-styled header bar. */
    GtkWidget *hb = gtk_header_bar_new();
    gtk_header_bar_set_show_close_button(GTK_HEADER_BAR(hb), TRUE);
    /* Use a custom title label so the text is never ellipsized to "CIPHER…". */
    GtkWidget *title_lbl = gtk_label_new("CIPHERS  \xC2\xB7  v" CIPHERS_VERSION);
    gtk_label_set_ellipsize(GTK_LABEL(title_lbl), PANGO_ELLIPSIZE_NONE);
    gtk_style_context_add_class(gtk_widget_get_style_context(title_lbl), "hb-title");
    gtk_header_bar_set_custom_title(GTK_HEADER_BAR(hb), title_lbl);
    GtkWidget *hb_about = gtk_button_new_with_label("About");
    g_signal_connect(hb_about, "clicked", G_CALLBACK(on_about), app);
    gtk_header_bar_pack_end(GTK_HEADER_BAR(hb), hb_about);
    gtk_window_set_titlebar(GTK_WINDOW(app->window), hb);

    GtkWidget *root = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_style_context_add_class(gtk_widget_get_style_context(root), "ciphers-root");
    gtk_container_set_border_width(GTK_CONTAINER(root), 18);
    gtk_container_add(GTK_CONTAINER(app->window), root);

    /* Brand banner */
    GtkWidget *brand = gtk_label_new("\xE2\x9D\x96 C I P H E R S");
    gtk_label_set_xalign(GTK_LABEL(brand), 0.5);
    gtk_style_context_add_class(gtk_widget_get_style_context(brand), "brand");
    gtk_box_pack_start(GTK_BOX(root), brand, FALSE, FALSE, 0);
    GtkWidget *sub = gtk_label_new("SECURE  FILE  ENCRYPTION");
    gtk_label_set_xalign(GTK_LABEL(sub), 0.5);
    gtk_style_context_add_class(gtk_widget_get_style_context(sub), "subtitle");
    gtk_box_pack_start(GTK_BOX(root), sub, FALSE, FALSE, 0);
    GtkWidget *sep = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_box_pack_start(GTK_BOX(root), sep, FALSE, FALSE, 6);

    /* Mode selection */
    GtkWidget *mode_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    app->radio_encrypt = gtk_radio_button_new_with_label(NULL, "Encrypt");
    app->radio_decrypt = gtk_radio_button_new_with_label_from_widget(
        GTK_RADIO_BUTTON(app->radio_encrypt), "Decrypt");
    gtk_box_pack_start(GTK_BOX(mode_box), app->radio_encrypt, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(mode_box), app->radio_decrypt, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(root), labeled_row("Operation:", mode_box, NULL), FALSE, FALSE, 0);

    /* Input file */
    app->in_entry = gtk_entry_new();
    GtkWidget *in_btn = gtk_button_new_with_label("Browse…");
    g_signal_connect(in_btn, "clicked", G_CALLBACK(on_browse_in), app);
    gtk_box_pack_start(GTK_BOX(root), labeled_row("Input file:", app->in_entry, in_btn), FALSE, FALSE, 0);

    /* Output file */
    app->out_entry = gtk_entry_new();
    GtkWidget *out_btn = gtk_button_new_with_label("Browse…");
    g_signal_connect(out_btn, "clicked", G_CALLBACK(on_browse_out), app);
    gtk_box_pack_start(GTK_BOX(root), labeled_row("Output file:", app->out_entry, out_btn), FALSE, FALSE, 0);

    /* Cipher */
    app->cipher_combo = gtk_combo_box_text_new();
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(app->cipher_combo), "1", "AES-256-GCM (default)");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(app->cipher_combo), "2", "XChaCha20-Poly1305");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(app->cipher_combo), "3", "ChaCha20-Poly1305");
    gtk_combo_box_set_active_id(GTK_COMBO_BOX(app->cipher_combo), "1");
    gtk_box_pack_start(GTK_BOX(root), labeled_row("Cipher:", app->cipher_combo, NULL), FALSE, FALSE, 0);

    /* KDF level */
    app->kdf_combo = gtk_combo_box_text_new();
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(app->kdf_combo), "0", "Basic (256 MiB)");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(app->kdf_combo), "1", "Medium (1 GiB, parallel) — minimum");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(app->kdf_combo), "2", "Strong (4 GiB, parallel)");
    gtk_combo_box_set_active_id(GTK_COMBO_BOX(app->kdf_combo), "1");
    gtk_box_pack_start(GTK_BOX(root), labeled_row("Key strength:", app->kdf_combo, NULL), FALSE, FALSE, 0);

    /* Post-quantum hybrid KEM (Kyber-1024 + X448). When enabled, the AEAD key
     * comes from a hybrid KEM whose secret key is wrapped by the password;
     * decryption auto-detects it from the file header. */
    app->hybrid_check = gtk_check_button_new_with_label(
        "Post-quantum hybrid (Kyber-1024 + X448)");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(app->hybrid_check), TRUE);
    gtk_box_pack_start(GTK_BOX(root), labeled_row("Hybrid PQC:", app->hybrid_check, NULL), FALSE, FALSE, 0);

    /* Password + reveal. The entry stores its text in a libsodium-backed
     * secure buffer (locked, non-dumpable, zeroed on free) rather than the
     * default heap buffer. */
    GtkEntryBuffer *pass_buf = secure_entry_buffer_new();
    app->pass_entry = gtk_entry_new_with_buffer(pass_buf);
    g_object_unref(pass_buf);   /* the entry now holds the reference */
    gtk_entry_set_visibility(GTK_ENTRY(app->pass_entry), FALSE);
    gtk_entry_set_input_purpose(GTK_ENTRY(app->pass_entry), GTK_INPUT_PURPOSE_PASSWORD);
    app->reveal_check = gtk_check_button_new_with_label("Reveal");
    g_signal_connect(app->reveal_check, "toggled", G_CALLBACK(on_reveal_toggled), app);
    gtk_box_pack_start(GTK_BOX(root),
                       labeled_row("Password:", app->pass_entry, app->reveal_check),
                       FALSE, FALSE, 0);

    /* Action button */
    app->run_button = gtk_button_new_with_label("ENCRYPT");
    gtk_widget_set_hexpand(app->run_button, TRUE);
    gtk_style_context_add_class(gtk_widget_get_style_context(app->run_button), "action-button");
    g_signal_connect(app->run_button, "clicked", G_CALLBACK(on_run), app);
    gtk_box_pack_start(GTK_BOX(root), app->run_button, FALSE, FALSE, 8);

    /* Progress + status. show_text gives a live percentage / byte readout,
     * useful for large files. */
    app->progress = gtk_progress_bar_new();
    gtk_progress_bar_set_show_text(GTK_PROGRESS_BAR(app->progress), TRUE);
    gtk_progress_bar_set_text(GTK_PROGRESS_BAR(app->progress), "idle");
    gtk_box_pack_start(GTK_BOX(root), app->progress, FALSE, FALSE, 0);
    app->status = gtk_label_new("Ready.");
    gtk_label_set_xalign(GTK_LABEL(app->status), 0.0);
    gtk_label_set_line_wrap(GTK_LABEL(app->status), TRUE);
    gtk_box_pack_start(GTK_BOX(root), app->status, FALSE, FALSE, 0);

    g_signal_connect(app->radio_encrypt, "toggled", G_CALLBACK(on_mode_toggled), app);
    g_signal_connect(app->radio_decrypt, "toggled", G_CALLBACK(on_mode_toggled), app);
    g_signal_connect(app->window, "destroy", G_CALLBACK(on_window_destroy), app);

    gtk_widget_show_all(app->window);
}

int main(int argc, char **argv) {
    if (ciphers_init() != 0) {
        g_printerr("Failed to initialise crypto library.\n");
        return 1;
    }
    GtkApplication *gapp = gtk_application_new(APP_ID, G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(gapp, "activate", G_CALLBACK(activate), NULL);
    int status = g_application_run(G_APPLICATION(gapp), argc, argv);
    g_object_unref(gapp);
    return status;
}
