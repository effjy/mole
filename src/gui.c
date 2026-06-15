/* mole-gui - GTK3 triage UI for the secrets scanner.
 *
 * The scan runs on a worker thread so the window stays responsive; results are
 * marshalled back to the main loop with g_idle_add and shown in a sortable,
 * severity-coloured tree. Only redacted secrets are ever displayed. */

#include "scan.h"
#include <gtk/gtk.h>
#include <string.h>

#ifndef VERSION
#define VERSION "0.0.0"
#endif

enum {
    COL_SEV_TEXT,
    COL_RULE,
    COL_FILE,
    COL_LINE,
    COL_ENTROPY,
    COL_TRIAGE,
    COL_SECRET,
    COL_PREVIEW,
    COL_SEV_INT,    /* for sorting + row colour */
    COL_PTR,        /* finding_t* */
    N_COLS
};

typedef struct {
    GtkWidget    *window;
    GtkWidget    *folder_btn;
    GtkWidget    *scan_btn;
    GtkWidget    *spinner;
    GtkWidget    *entropy_chk;
    GtkWidget    *all_chk;
    GtkWidget    *sev_combo;
    GtkWidget    *tree;
    GtkListStore *store;
    GtkWidget    *detail;
    GtkWidget    *statusbar;
    guint         status_ctx;

    findings_t   *findings;   /* owned; freed/replaced on each scan */
    char          root[MOLE_MAX_PATH];
} App;

/* ---- worker-thread plumbing ------------------------------------------- */

typedef struct {
    App        *app;
    char        root[MOLE_MAX_PATH];
    scan_opts   opts;
    findings_t *result;
} scan_job;

static const char *sev_rgba(severity_t s)
{
    switch (s) {
        case SEV_CRITICAL: return "#b00020";
        case SEV_HIGH:     return "#d35400";
        case SEV_MEDIUM:   return "#b7950b";
        default:           return "#1f618d";
    }
}

static void set_status(App *a, const char *msg)
{
    gtk_statusbar_pop(GTK_STATUSBAR(a->statusbar), a->status_ctx);
    gtk_statusbar_push(GTK_STATUSBAR(a->statusbar), a->status_ctx, msg);
}

static void populate(App *a)
{
    gtk_list_store_clear(a->store);
    size_t shown = 0, by[4] = {0};
    for (finding_t *f = a->findings ? a->findings->head : NULL; f; f = f->next) {
        char entbuf[16];
        g_snprintf(entbuf, sizeof(entbuf), "%.2f", f->entropy);
        GtkTreeIter it;
        gtk_list_store_append(a->store, &it);
        gtk_list_store_set(a->store, &it,
            COL_SEV_TEXT, severity_name(f->severity),
            COL_RULE,     f->rule,
            COL_FILE,     f->path,
            COL_LINE,     (gint)f->line,
            COL_ENTROPY,  entbuf,
            COL_TRIAGE,   triage_name(f->triage),
            COL_SECRET,   f->redacted,
            COL_PREVIEW,  f->preview,
            COL_SEV_INT,  (gint)f->severity,
            COL_PTR,      f,
            -1);
        shown++;
        by[f->severity]++;
    }
    char msg[256];
    if (a->findings)
        g_snprintf(msg, sizeof(msg),
            "%zu finding(s)  -  %zu critical, %zu high, %zu medium, %zu low   "
            "(%zu files scanned, %zu skipped)",
            shown, by[SEV_CRITICAL], by[SEV_HIGH], by[SEV_MEDIUM], by[SEV_LOW],
            a->findings->files_scanned, a->findings->files_skipped);
    else
        g_snprintf(msg, sizeof(msg), "Scan failed.");
    set_status(a, msg);
}

/* Runs on the main loop once the worker thread finishes. */
static gboolean scan_done(gpointer data)
{
    scan_job *job = data;
    App *a = job->app;

    if (a->findings) findings_free(a->findings);
    a->findings = job->result;

    populate(a);

    gtk_spinner_stop(GTK_SPINNER(a->spinner));
    gtk_widget_hide(a->spinner);
    gtk_widget_set_sensitive(a->scan_btn, TRUE);
    gtk_widget_set_sensitive(a->folder_btn, TRUE);

    g_free(job);
    return G_SOURCE_REMOVE;
}

static gpointer scan_thread(gpointer data)
{
    scan_job *job = data;
    job->result = scan_run(job->root, &job->opts, NULL, NULL);
    g_idle_add(scan_done, job);
    return NULL;
}

static void on_scan(GtkButton *btn, gpointer data)
{
    (void)btn;
    App *a = data;

    char *folder = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(a->folder_btn));
    if (!folder) {
        set_status(a, "Choose a folder to scan first.");
        return;
    }
    g_strlcpy(a->root, folder, sizeof(a->root));
    g_free(folder);

    scan_job *job = g_new0(scan_job, 1);
    job->app = a;
    g_strlcpy(job->root, a->root, sizeof(job->root));
    job->opts = scan_default_opts();
    job->opts.entropy_scan =
        gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(a->entropy_chk));
    job->opts.walk.skip_vcs =
        !gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(a->all_chk));

    gtk_widget_set_sensitive(a->scan_btn, FALSE);
    gtk_widget_set_sensitive(a->folder_btn, FALSE);
    gtk_widget_show(a->spinner);
    gtk_spinner_start(GTK_SPINNER(a->spinner));
    set_status(a, "Scanning...");

    GThread *t = g_thread_new("mole-scan", scan_thread, job);
    g_thread_unref(t);
}

/* ---- severity filter -------------------------------------------------- */

static gboolean row_visible(GtkTreeModel *model, GtkTreeIter *iter, gpointer data)
{
    App *a = data;
    gint want = gtk_combo_box_get_active(GTK_COMBO_BOX(a->sev_combo)); /* 0=all */
    if (want <= 0) return TRUE;
    gint sev;
    gtk_tree_model_get(model, iter, COL_SEV_INT, &sev, -1);
    /* combo: 1=low,2=medium,3=high,4=critical -> min severity = want-1 */
    return sev >= want - 1;
}

static void on_filter_changed(GtkComboBox *c, gpointer data)
{
    (void)c;
    App *a = data;
    GtkTreeModel *m = gtk_tree_view_get_model(GTK_TREE_VIEW(a->tree));
    if (GTK_IS_TREE_MODEL_FILTER(m))
        gtk_tree_model_filter_refilter(GTK_TREE_MODEL_FILTER(m));
}

/* ---- selection detail ------------------------------------------------- */

static void on_selection(GtkTreeSelection *sel, gpointer data)
{
    App *a = data;
    GtkTreeModel *m;
    GtkTreeIter it;
    if (!gtk_tree_selection_get_selected(sel, &m, &it)) {
        gtk_label_set_text(GTK_LABEL(a->detail), "Select a finding to inspect.");
        return;
    }
    finding_t *f = NULL;
    gtk_tree_model_get(m, &it, COL_PTR, &f, -1);
    if (!f) return;

    char *txt = g_markup_printf_escaped(
        "<b>%s</b>  (%s)\n"
        "<tt>%s:%ld</tt>\n\n"
        "secret  : <tt>%s</tt>\n"
        "entropy : %.2f bits/char\n"
        "triage  : %s\n\n"
        "<i>%s</i>",
        f->rule, severity_name(f->severity),
        f->path, f->line,
        f->redacted, f->entropy, triage_name(f->triage),
        f->preview);
    gtk_label_set_markup(GTK_LABEL(a->detail), txt);
    g_free(txt);
}

/* ---- triage ----------------------------------------------------------- */

static void set_triage(App *a, triage_t t)
{
    GtkTreeSelection *sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(a->tree));
    GtkTreeModel *m;
    GtkTreeIter it;
    if (!gtk_tree_selection_get_selected(sel, &m, &it)) return;

    finding_t *f = NULL;
    gtk_tree_model_get(m, &it, COL_PTR, &f, -1);
    if (!f) return;
    f->triage = t;

    /* The view sits behind a filter model; convert to the child store iter. */
    GtkTreeIter child = it;
    if (GTK_IS_TREE_MODEL_FILTER(m))
        gtk_tree_model_filter_convert_iter_to_child_iter(
            GTK_TREE_MODEL_FILTER(m), &child, &it);
    gtk_list_store_set(a->store, &child, COL_TRIAGE, triage_name(t), -1);
    on_selection(sel, a);
}

static void on_mark_leak(GtkButton *b, gpointer d)  { (void)b; set_triage(d, TRIAGE_LEAK); }
static void on_mark_false(GtkButton *b, gpointer d) { (void)b; set_triage(d, TRIAGE_FALSE); }
static void on_mark_ignore(GtkButton *b, gpointer d){ (void)b; set_triage(d, TRIAGE_IGNORED); }

/* ---- CSV export ------------------------------------------------------- */

static void on_export(GtkButton *btn, gpointer data)
{
    (void)btn;
    App *a = data;
    if (!a->findings || a->findings->count == 0) {
        set_status(a, "Nothing to export.");
        return;
    }
    GtkWidget *dlg = gtk_file_chooser_dialog_new(
        "Export findings (CSV)", GTK_WINDOW(a->window),
        GTK_FILE_CHOOSER_ACTION_SAVE,
        "_Cancel", GTK_RESPONSE_CANCEL, "_Save", GTK_RESPONSE_ACCEPT, NULL);
    gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(dlg), "mole-findings.csv");
    gtk_file_chooser_set_do_overwrite_confirmation(GTK_FILE_CHOOSER(dlg), TRUE);

    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_ACCEPT) {
        char *path = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dlg));
        FILE *fp = fopen(path, "w");
        if (fp) {
            fprintf(fp, "severity,rule,file,line,entropy,triage,secret\n");
            for (finding_t *f = a->findings->head; f; f = f->next)
                fprintf(fp, "%s,\"%s\",\"%s\",%ld,%.2f,%s,\"%s\"\n",
                        severity_name(f->severity), f->rule, f->path,
                        f->line, f->entropy, triage_name(f->triage),
                        f->redacted);
            fclose(fp);
            set_status(a, "Findings exported.");
        } else {
            set_status(a, "Could not write file.");
        }
        g_free(path);
    }
    gtk_widget_destroy(dlg);
}

/* ---- colour cell data func ------------------------------------------- */

static void sev_cell_func(GtkTreeViewColumn *col, GtkCellRenderer *cell,
                          GtkTreeModel *m, GtkTreeIter *it, gpointer data)
{
    (void)col; (void)data;
    gint sev;
    gtk_tree_model_get(m, it, COL_SEV_INT, &sev, -1);
    g_object_set(cell, "foreground", sev_rgba((severity_t)sev),
                       "foreground-set", TRUE, NULL);
}

/* ---- UI construction -------------------------------------------------- */

static GtkWidget *make_toolbar(App *a)
{
    GtkWidget *bar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_container_set_border_width(GTK_CONTAINER(bar), 6);

    a->folder_btn = gtk_file_chooser_button_new(
        "Folder to scan", GTK_FILE_CHOOSER_ACTION_SELECT_FOLDER);
    gtk_box_pack_start(GTK_BOX(bar), a->folder_btn, FALSE, FALSE, 0);

    a->scan_btn = gtk_button_new_with_label("Scan");
    gtk_box_pack_start(GTK_BOX(bar), a->scan_btn, FALSE, FALSE, 0);

    a->spinner = gtk_spinner_new();
    gtk_box_pack_start(GTK_BOX(bar), a->spinner, FALSE, FALSE, 0);

    a->entropy_chk = gtk_check_button_new_with_label("Entropy scan");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(a->entropy_chk), TRUE);
    gtk_box_pack_start(GTK_BOX(bar), a->entropy_chk, FALSE, FALSE, 0);

    a->all_chk = gtk_check_button_new_with_label("Include .git/vendor");
    gtk_box_pack_start(GTK_BOX(bar), a->all_chk, FALSE, FALSE, 0);

    GtkWidget *flbl = gtk_label_new("Min severity:");
    gtk_box_pack_start(GTK_BOX(bar), flbl, FALSE, FALSE, 0);
    a->sev_combo = gtk_combo_box_text_new();
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(a->sev_combo), "All");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(a->sev_combo), "Low+");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(a->sev_combo), "Medium+");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(a->sev_combo), "High+");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(a->sev_combo), "Critical");
    gtk_combo_box_set_active(GTK_COMBO_BOX(a->sev_combo), 0);
    gtk_box_pack_start(GTK_BOX(bar), a->sev_combo, FALSE, FALSE, 0);

    GtkWidget *exp = gtk_button_new_with_label("Export CSV");
    gtk_box_pack_end(GTK_BOX(bar), exp, FALSE, FALSE, 0);
    g_signal_connect(exp, "clicked", G_CALLBACK(on_export), a);

    g_signal_connect(a->scan_btn, "clicked", G_CALLBACK(on_scan), a);
    g_signal_connect(a->sev_combo, "changed", G_CALLBACK(on_filter_changed), a);
    return bar;
}

static void add_text_col(App *a, const char *title, int col, int sortable)
{
    GtkCellRenderer *r = gtk_cell_renderer_text_new();
    GtkTreeViewColumn *c =
        gtk_tree_view_column_new_with_attributes(title, r, "text", col, NULL);
    gtk_tree_view_column_set_resizable(c, TRUE);
    if (sortable) gtk_tree_view_column_set_sort_column_id(c, col);
    if (col == COL_SEV_TEXT)
        gtk_tree_view_column_set_cell_data_func(c, r, sev_cell_func, NULL, NULL);
    gtk_tree_view_append_column(GTK_TREE_VIEW(a->tree), c);
}

static GtkWidget *make_tree(App *a)
{
    a->store = gtk_list_store_new(N_COLS,
        G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_INT,
        G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
        G_TYPE_INT, G_TYPE_POINTER);

    GtkTreeModel *filter =
        gtk_tree_model_filter_new(GTK_TREE_MODEL(a->store), NULL);
    gtk_tree_model_filter_set_visible_func(
        GTK_TREE_MODEL_FILTER(filter), row_visible, a, NULL);

    a->tree = gtk_tree_view_new_with_model(filter);
    g_object_unref(filter);

    add_text_col(a, "Severity", COL_SEV_TEXT, 1);
    add_text_col(a, "Rule",     COL_RULE,     1);
    add_text_col(a, "File",     COL_FILE,     1);
    add_text_col(a, "Line",     COL_LINE,     1);
    add_text_col(a, "Entropy",  COL_ENTROPY,  1);
    add_text_col(a, "Triage",   COL_TRIAGE,   1);
    add_text_col(a, "Secret",   COL_SECRET,   0);
    add_text_col(a, "Context",  COL_PREVIEW,  0);

    GtkTreeSelection *sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(a->tree));
    g_signal_connect(sel, "changed", G_CALLBACK(on_selection), a);

    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
        GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_container_add(GTK_CONTAINER(scroll), a->tree);
    return scroll;
}

static GtkWidget *make_detail(App *a)
{
    GtkWidget *frame = gtk_frame_new("Detail");
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_container_set_border_width(GTK_CONTAINER(box), 8);

    a->detail = gtk_label_new("Select a finding to inspect.");
    gtk_label_set_xalign(GTK_LABEL(a->detail), 0.0);
    gtk_label_set_line_wrap(GTK_LABEL(a->detail), TRUE);
    gtk_label_set_selectable(GTK_LABEL(a->detail), TRUE);
    gtk_box_pack_start(GTK_BOX(box), a->detail, TRUE, TRUE, 0);

    GtkWidget *btns = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    GtkWidget *leak  = gtk_button_new_with_label("Mark Leak");
    GtkWidget *fp    = gtk_button_new_with_label("False Positive");
    GtkWidget *ign   = gtk_button_new_with_label("Ignore");
    gtk_box_pack_start(GTK_BOX(btns), leak, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(btns), fp,   FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(btns), ign,  FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), btns, FALSE, FALSE, 0);

    g_signal_connect(leak, "clicked", G_CALLBACK(on_mark_leak), a);
    g_signal_connect(fp,   "clicked", G_CALLBACK(on_mark_false), a);
    g_signal_connect(ign,  "clicked", G_CALLBACK(on_mark_ignore), a);

    gtk_container_add(GTK_CONTAINER(frame), box);
    return frame;
}

static void activate(GtkApplication *app, gpointer data)
{
    App *a = data;
    a->window = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(a->window), "mole - secrets scanner");
    gtk_window_set_default_size(GTK_WINDOW(a->window), 1000, 640);
    gtk_window_set_icon_name(GTK_WINDOW(a->window), "mole");

    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_box_pack_start(GTK_BOX(vbox), make_toolbar(a), FALSE, FALSE, 0);

    GtkWidget *paned = gtk_paned_new(GTK_ORIENTATION_VERTICAL);
    gtk_paned_pack1(GTK_PANED(paned), make_tree(a), TRUE, TRUE);
    gtk_paned_pack2(GTK_PANED(paned), make_detail(a), FALSE, TRUE);
    gtk_paned_set_position(GTK_PANED(paned), 420);
    gtk_box_pack_start(GTK_BOX(vbox), paned, TRUE, TRUE, 0);

    a->statusbar = gtk_statusbar_new();
    a->status_ctx = gtk_statusbar_get_context_id(
        GTK_STATUSBAR(a->statusbar), "mole");
    gtk_box_pack_start(GTK_BOX(vbox), a->statusbar, FALSE, FALSE, 0);
    set_status(a, "Pick a folder and press Scan.");

    gtk_container_add(GTK_CONTAINER(a->window), vbox);
    gtk_widget_show_all(a->window);
    gtk_widget_hide(a->spinner);   /* shown only while scanning */

    /* If a path was given on the command line, pre-load and scan it. */
    if (a->root[0]) {
        gtk_file_chooser_set_filename(GTK_FILE_CHOOSER(a->folder_btn), a->root);
        on_scan(GTK_BUTTON(a->scan_btn), a);
    }
}

int main(int argc, char **argv)
{
    App a;
    memset(&a, 0, sizeof(a));

    /* Optional startup path: scan it as soon as the window is shown. We parse
     * it ourselves and hand GtkApplication an empty argv so its own command
     * line handling does not complain about the positional argument. */
    if (argc > 1 && argv[1][0] != '-')
        g_strlcpy(a.root, argv[1], sizeof(a.root));

    GtkApplication *app =
        gtk_application_new("org.toolkit.mole", G_APPLICATION_NON_UNIQUE);
    g_signal_connect(app, "activate", G_CALLBACK(activate), &a);
    int rc = g_application_run(G_APPLICATION(app), 1, argv);

    if (a.findings) findings_free(a.findings);
    rules_free();
    g_object_unref(app);
    return rc;
}
