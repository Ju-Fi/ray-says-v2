#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <stdio.h>
#include "markov.h"

void
_dappend(void **out_data, size_t *out_count, size_t *out_cap, size_t element_size, void *element)
{
    char *data = *out_data;
    size_t count = *out_count, cap = *out_cap;

    if (count >= cap) {
        cap = cap == 0 ? count + 16 : count * 2;
        data = realloc(data, cap * element_size);

        assert(data);
    }

    memcpy(data + (element_size * count), element, element_size);

    *out_data = data;
    *out_count = ++count;
    *out_cap = cap;
}

void
_da_conc(void **out_data,
         size_t *out_count,
         size_t *out_cap,
         size_t element_size,
         void const *add_data,
         size_t add_data_count)
{
    char *data = *out_data;
    size_t count = *out_count + add_data_count, cap = *out_cap;

    if (count >= cap) {
        cap = cap == 0 ? count + 16 : count * 2;
        data = realloc(data, cap * element_size);

        assert(data && "TODO Error handling");
    }

    memcpy(
        data + (element_size * (count - add_data_count)),
        add_data,
        element_size * add_data_count
    );

    *out_data = data;
    *out_count = count;
    *out_cap = cap;
}

void
sb_append(String_Builder *sb, char c)
{
    if (!sb) return;

    if (sb->count + 1 >= sb->cap) {
        sb->cap = sb->cap == 0 ? sb->count + 12 : sb->count * 2;
        sb->data = realloc(sb->data, sb->cap);

        assert(sb->data);
    }

    sb->data[sb->count++] = c;
    sb->data[sb->count] = '\0';
}

bool
sv_equals(String_View const *a, String_View const *b)
{
    if (!a || !b || a->count != b->count) {
        return false;
    }

    for (size_t i = 0; i < a->count; i++) {
        if (a->data[i] != b->data[i]) {
            return false;
        }
    }

    return true;
}

String_View
sv_from_sb(String_Builder const *sb)
{
    String_View result = {0};

    if (sb) {
        result.data = sb->data;
        result.count = sb->count;
    }

    return result;
}

static String_Builder
next_word(FILE *stream)
{
    String_Builder token = {0};

    for (char c = fgetc(stream);
         c != ' ' && c != '\n' && c != EOF;
         c = fgetc(stream)) {
        sb_append(&token, c);
    }

    return token;
}

static uint32_t
string_hash(char const *key, size_t length)
{
    uint32_t hash = 1315423911;

    for (size_t i = 0; i < length; i++) {
        hash ^= ((hash << 5) + key[i] + (hash >> 2));
    }

    return hash;
}

Markov_Table_Entry *
markov_table_get(Markov_Table *tbl, String_View const *key)
{
    bool looping_around = false;
    size_t i, index;
    Markov_Table_Entry *result;

    assert(tbl && key);
    index = string_hash(key->data, key->count) % tbl->count;
    for (i = index;
         (looping_around ? i < index : i <= tbl->count)
             && (i < tbl->count && (!tbl->data[i].token.data
                 || !sv_equals(&tbl->data[i].token, key)));
         i++) {
        if (i == tbl->count) {
            looping_around = true;
            i = 0;
            continue;
        }
    }

    if (i == tbl->count) {
        // insert new
        result = markov_table_insert(tbl, key, NULL);
    } else {
        result = tbl->data + i;
    }
    return result;
}

Markov_Table_Entry *
markov_table_insert(Markov_Table *tbl, String_View const *token, String_View const *next_token)
{
    Token_Weight next_token_weight = {0};
    bool looping_around = false;
    size_t i, index;

    assert(tbl && token && "TODO Error checking");
    index = string_hash(token->data, token->count) % tbl->count;
    for (i = index; looping_around ? i < index : i <= tbl->count; i++) {
        if (i == tbl->count) {
            looping_around = true;
            i = 0;
            continue;
        }

        if (tbl->data[i].token.data == NULL) {
            // New entry
            tbl->data[i] = (Markov_Table_Entry){.token = *token};
            if (next_token) {
                next_token_weight.entry = markov_table_get(tbl, next_token); // Try to find the entry for 'next_token', otherwise creates an entry
                next_token_weight.occurrences = 1;
                dappend(&tbl->data[i].subsequents, next_token_weight);
            }

            break;
        } else if (sv_equals(token, &tbl->data[i].token)) {
            // Update entry with new subsequent/increment subsequent
            Markov_Table_Entry *entry = tbl->data + i;
            bool subsequent_exists = false;
            size_t j;

            for (j = 0; j < entry->subsequents.count && !subsequent_exists; j++) {
                subsequent_exists = sv_equals(
                    &entry->subsequents.data[j].entry->token,
                    next_token
                );
            }

            if (subsequent_exists) {
                // update
                j--;
                entry->subsequents.data[j].occurrences++;
            } else {
                // insert new
                next_token_weight.entry = markov_table_get(tbl, next_token);
                next_token_weight.occurrences = 1;

                dappend(&entry->subsequents, next_token_weight);
            }

            break;
        }
    }

    return tbl->data + i;
}

Markov_Table
markov_table_create(FILE *stream)
{
    Markov_Table tbl = {0};
    String_Builder cur_token = {0}, prev_token = {0};

    for (char c = fgetc(stream); c != EOF; c = fgetc(stream)) {
        if (c == ' ' || c == '\n') {
            tbl.count++;
        } else if (c == '.') {
            tbl.count--;
        }
    }

    //tbl.count = tbl.count * 2 + 1;

    tbl.data = malloc(tbl.count * sizeof(*tbl.data));
    memset(tbl.data, 0, tbl.count * sizeof(*tbl.data));
    rewind(stream);

    cur_token = next_word(stream);

    while (!feof(stream)) {
        String_Builder next_token = next_word(stream);

        if (!next_token.cap) {
            break;
        }

        sb_append(&cur_token, ' ');

        for (size_t i = 0; i < next_token.count; i++) {
            sb_append(&cur_token, next_token.data[i]);
        }

        if (prev_token.cap) {
            String_View p = sv_from_sb(&prev_token), c = sv_from_sb(&cur_token);
            markov_table_insert(&tbl, &p, &c);
        }

        prev_token = cur_token;
        cur_token = next_token.data[next_token.count - 1] == '.' ? next_word(stream) : next_token;
    }

    return tbl;
}

Byte_Buffer
markov_table_serialize(Markov_Table const *tbl, FILE *output)
{
    Byte_Buffer buf = {0};

    da_conc(&buf, &tbl->count, sizeof(tbl->count));
    for (size_t i = 0; i < tbl->count; i++) {
        String_View token = tbl->data[i].token;
        Token_Weights subs = tbl->data[i].subsequents;

        /* Write Markov_Table_Entry token */
        da_conc(&buf, &token.count, sizeof(token.count));
        if (token.data) {
            da_conc(&buf, token.data, token.count + 1); // +1 for NUL
        } else {
            /* char nul = '\0'; */
            /* da_conc(&buf, &nul, 1); */
        }

        /* Write Markov_Table_Entry subsequents */
        da_conc(&buf, &subs.count, sizeof(subs.count));
        for (size_t j = 0; j < subs.count; j++) {
            uintptr_t entry_idx = subs.data[j].entry - tbl->data; // Write index instead of pointer
            uint64_t occurrences = subs.data[j].occurrences;
            /* Write Token_Weight */
            da_conc(&buf, &entry_idx, sizeof(entry_idx));
            da_conc(&buf, &occurrences, sizeof(occurrences));
        }
    }

    fwrite(buf.data, sizeof(*buf.data), buf.count, output);
    return buf;
}

ssize_t
bb_read(Byte_Buffer *bytes, void *buf, size_t n)
{
    ssize_t result;

    if (!bytes || !bytes->data || !buf) {
        result = -1;
    } else {
        if (bytes->count < n) {
            n = bytes->count;
        }
        memcpy(buf, bytes->data, n);
        bytes->data += n;
        bytes->count -= n;
        result = n;
    }

    return result;
}
#define BB_READ_INTO(buf, dest) bb_read((buf), &(dest), sizeof((dest)))

Markov_Table
markov_table_deserialize(Byte_Buffer bytes)
{
    Markov_Table result = {0};

    assert(bytes.count >= sizeof(result.count));

    assert(BB_READ_INTO(&bytes, result.count) == sizeof(result.count));
    result.data = malloc(result.count * sizeof(*result.data));
    assert(result.data);

    for (size_t i = 0; i < result.count; i++) {
        String_View token = {0};
        Token_Weights subs = {0};
        char *s = NULL;

        BB_READ_INTO(&bytes, token.count);
        s = token.count ? malloc(token.count + 1) : NULL;
        bb_read(&bytes, s, token.count + 1);
        token.data = s;
        result.data[i].token = token;

        BB_READ_INTO(&bytes, subs.count);
        subs.data = subs.count ? malloc(subs.count * sizeof(*subs.data)) : NULL;
        for (size_t j = 0; j < subs.count; j++) {
            Token_Weight tw = {0};
            uintptr_t entry_idx;

            BB_READ_INTO(&bytes, entry_idx);
            BB_READ_INTO(&bytes, tw.occurrences);
            tw.entry = result.data + entry_idx;

            subs.data[j] = tw;
        }

        result.data[i].subsequents = subs;
    }

    return result;
}

static void
print_table(Markov_Table *tbl)
{
    for (size_t i = 0; i < tbl->count; i++) {
        printf("%lu: {token = \"%s\", [", i, tbl->data[i].token.data);
        for (size_t j = 0; j < tbl->data[i].subsequents.count; j++) {
            Token_Weight *tw = &tbl->data[i].subsequents.data[j];
            printf("{entry = \"%s\", n = %llu}, ", tw->entry->token.data, tw->occurrences);
        }
        printf("]}\n");
    }

}

int
main(void)
{
    FILE *input = fopen("trunc_ray_sentences.txt", "r");
    FILE *output = fopen("weights_bin", "w");
    Byte_Buffer buf;

    assert(input && output && "TODO error handling");

    Markov_Table t = markov_table_create(input);
#if 0
    print_table(&t);
#else
    buf = markov_table_serialize(&t, output);
    Markov_Table deserialized = markov_table_deserialize(buf);
    print_table(&deserialized);
#endif
    fclose(input);
    fclose(output);
    return 0;
}
