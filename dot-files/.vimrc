"so /home/lekan/dotfiles/vim/vimrc.vim
set nocompatible              " be iMproved, required
filetype off                  " required

"split navigations
nnoremap <C-J> <C-W><C-J>
nnoremap <C-K> <C-W><C-K>
nnoremap <C-L> <C-W><C-L>
nnoremap <C-H> <C-W><C-H>

imap <F6> <Esc>:w<CR>:!clear;py shell %<CR>

imap jk <Esc>
set splitbelow 
set splitright

" Set folding method
set foldmethod=indent
set foldlevel=99

noremap <leader>/ :Commentary<cr>

" Enable folding with the spacebar
nnoremap <space> za

" make docstring of folded code show
let g:SimpylFold_docstring_preview=1

" add pep8 indentation
au BufNewFile,BufRead *.py
    \ set tabstop=4
    \ set softtabstop=4
    \ set shiftwidth=4
    \ set textwidth=79
    \ set expandtab
    \ set autoindent
    \ set fileformat=unix


" add file association for full staxck development
au BufNewFile,BufRead *.js, *.html, *.css *.yml *.yaml
    \ set tabstop=2
    \ set softtabstop=2
    \ set shiftwidth=2


" add jinja support
au BufNewFile,BufRead *.html,*.htm,*.shtml,*.stm, *.j2 set ft=jinja

" add yaml stuffs
au! BufNewFile,BufReadPost *.{yaml,yml} set filetype=yaml foldmethod=indent
autocmd FileType yaml setlocal ts=2 sts=2 sw=2 expandtab

" encoding 
set encoding=utf-8


set rtp+=/usr/local/lib/python2.7/dist-packages/powerline/bindings/vim/

" Always show statusline
 set laststatus=2

" " Use 256 colours (Use this setting only if your terminal supports 256
" colours)
set t_Co=256

let python_highlight_all=1
syntax on

" turn on line numbering
set nu

"make spacebar do go-to definition
let g:ycm_autoclose_preview_window_after_completion=1
map <leader>g  :YcmCompleter GoToDefinitionElseDeclaration<CR>
 
" Make the system clipboard the default one
set clipboard=unnamed


python3 << endpy
import os
import sys
if 'VIRTUAL_ENV' in os.environ:
    project_base_dir = os.environ['VIRTUAL_ENV']
    activate_this = os.path.join(project_base_dir, 'bin/activate_this.py')
    execfile(activate_this, dict(__file__=activate_this))
endpy

" shout when whitespaces are left wandering about like a stray cat
au BufRead,BufNewFile *.py,*.pyw,*.c,*.h match BadWhitespace /\s\+$/

" set the runtime path to include Vundle and initialize
set rtp+=~/.vim/bundle/Vundle.vim
call vundle#begin()
" alternatively, pass a path where Vundle should install plugins
"call vundle#begin('~/some/path/here')

" let Vundle manage Vundle, required
Plugin 'VundleVim/Vundle.vim'

" The following are examples of different formats supported.
" Keep Plugin commands between vundle#begin/end.
" plugin on GitHub repo
" plugin from http://vim-scripts.org/vim/scripts.html
" Plugin 'L9'
" Git plugin not hosted on GitHub

" docker plugin
Plugin 'ekalinin/Dockerfile.vim'

Plugin 'git://git.wincent.com/command-t.git'
" git repos on your local machine (i.e. when working on your own plugin)
" Plugin 'file:///home/gmarik/path/to/plugin'
" The sparkup vim script is in a subdirectory of this repo called vim.
" Pass the path to set the runtimepath properly.
Plugin 'rstacruz/sparkup', {'rtp': 'vim/'}
" Install L9 and avoid a Naming conflict if you've already installed a
" different version somewhere else.
" Plugin 'ascenator/L9', {'name': 'newL9'}

"best folding plugin
Plugin 'tmhedberg/SimpylFold'

" Auto indentation of python code
Plugin 'vim-scripts/indentpython.vim'

" auto complete python code
Plugin 'Valloric/YouCompleteMe'

" syntax checker
Plugin 'vim-syntastic/syntastic'

" Pep8 plugin for syntax 
Plugin 'nvie/vim-flake8'

" vim plugin for using git commands inside vim console
Plugin 'tpope/vim-fugitive'

" The powerful powerline plugin
Plugin 'Lokaltog/powerline', {'rtp': 'powerline/bindings/vim/'}

" proper file tree
Plugin 'scrooloose/nerdtree'

Plugin 'jistr/vim-nerdtree-tabs'

" Searching plugin to search any shit
Plugin 'kien/ctrlp.vim'

" vim plugin for golang
Plugin 'fatih/vim-go'

Plugin 'nsf/gocode', {'rtp': 'vim/'}

Plugin 'tpope/vim-commentary'

" hide .pyc files
let NERDTreeIgnore=['\.pyc$', '\~$'] "ignore files in NERDTree

let g:go_debug=['shell-commands']

" color shit
Plugin 'jnurmine/Zenburn'
Plugin 'altercation/vim-colors-solarized'

" yaml plugin
Plugin 'mrk21/yaml-vim'

" jinja templating system plugin
Plugin 'lepture/vim-jinja'

Plugin 'hiphish/jinja.vim'
" switch btw color schemes with f5
"call togglebg#map("<F5>")

" All of your Plugins must be added before the following line
call vundle#end()            " required
filetype plugin indent on    " required
" To ignore plugin indent changes, instead use:
"filetype plugin on
"
" Brief help
" :PluginList       - lists configured plugins
" :PluginInstall    - installs plugins; append `!` to update or just :PluginUpdate
" :PluginSearch foo - searches for foo; append `!` to refresh local cache
" :PluginClean      - confirms removal of unused plugins; append `!` to auto-approve removal
"
" see :h vundle for more details or wiki for FAQ
" Put your non-Plugin stuff after this line
Plugin 'wakatime/vim-wakatime'

" plugin for bash scripting support
Plugin 'bash-support.vim'

