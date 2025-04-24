if( ! bmexp_supports.allow_autocomplete && wp !== undefined && wp.hooks !== undefined && wp.hooks.removeFilter !== undefined ){
    const remove_user_autocomplete = wp.hooks.removeFilter(
        'editor.Autocomplete.completers',
        'editor/autocompleters/set-default-completers'
    );
}
