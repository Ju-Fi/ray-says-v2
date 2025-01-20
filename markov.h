#ifndef MARKOV_H_
#define MARKOV_H_

typedef struct {
    char *data;
    size_t count;
    size_t cap;
} String_Builder;

typedef struct {
    char const *data;
    size_t count;
} String_View;

typedef struct {
    uint8_t *data;
    size_t count;
    size_t cap;
} Byte_Buffer;

typedef struct Markov_Table_Entry Markov_Table_Entry;

typedef struct {
    Markov_Table_Entry *entry;
    uint64_t occurrences;
} Token_Weight;

typedef struct {
    Token_Weight *data;
    size_t count;
    size_t cap;
} Token_Weights;

typedef struct Markov_Table_Entry {
    String_View token;
    Token_Weights subsequents;
} Markov_Table_Entry;

typedef struct {
    size_t count;
    Markov_Table_Entry *data;
} Markov_Table;

void _dappend(void **out_data, size_t *out_count, size_t *out_cap, size_t element_size, void *element);
#define dappend(da, x) _dappend((void**)&(da)->data, &(da)->count, &(da)->cap, sizeof(*((da)->data)), &(x))
void _da_conc(void **out_data, size_t *out_count, size_t *out_cap, size_t element_size, void const *add_data, size_t add_data_count);
#define da_conc(da, xs, n) _da_conc((void**)&(da)->data, &(da)->count, &(da)->cap, sizeof(*((da)->data)), (xs), (n))
void sb_append(String_Builder *sb, char c);
bool sv_equals(String_View const *a, String_View const *b);
String_View sv_from_sb(String_Builder const *sb);

Markov_Table_Entry *markov_table_insert(Markov_Table *tbl, String_View const *token, String_View const *next_token);
Markov_Table_Entry *markov_table_get(Markov_Table *tbl, String_View const *key);
Markov_Table markov_table_create(FILE *stream);
Byte_Buffer markov_table_serialize(Markov_Table const *tbl, FILE *output);


#endif // MARKOV_H_
