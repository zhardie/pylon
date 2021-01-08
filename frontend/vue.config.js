module.exports = {
  devServer: {
    public: '192.168.1.44:8080',
    publicPath: 'http://192.168.1.44:8080/',
    disableHostCheck: true,
    watchOptions: {
      poll: true
    }
  },
  css: {
    loaderOptions: {
      sass: {
        data: `@import "~@/sass/main.scss"`,
      },
    },
  },
  "transpileDependencies": [
    "vuetify"
  ]
}