import { defineConfig } from 'eslint/config'
import vue from 'eslint-plugin-vue'
import skipFormatting from '@vue/eslint-config-prettier/skip-formatting'

export default defineConfig([
  {
    files: ['**/*.{js,jsx,cjs,mjs,vue}'],
    ignores: ['dist/**']
  },
  ...vue.configs['flat/essential'],
  skipFormatting
])
