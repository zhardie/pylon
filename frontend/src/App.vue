<style>
.row {
  margin-left: 0;
  margin-right: 0;
}</style>

<template>
  <v-app>
    <div v-if="logged_in == true">
      <Navbar />
      <v-content>
        <router-view @snackbar="showSnackBar" />
      </v-content>
    </div>
    <div v-else>
      <Login :logged_in.sync="logged_in" />
    </div>
  </v-app>
</template>

<script>
import Navbar from './components/Navbar';

export default {
  name: 'App',
  components: {
    Navbar
  },
  mounted: function () {
    if (localStorage.getItem('dark') == 'true') {
      this.$vuetify.theme.dark = true
    } else {
      this.$vuetify.theme.dark = false
    }
  },
  data () {
    return {
      logged_in: true
    }
  },
  methods: {
    showSnackBar (val) {
      console.log(val)
    }
  },
  computed: {
    dark () {
      return this.$vuetify.theme.dark
    }
  },
  watch: {
    dark () {
      localStorage.setItem('dark', this.$vuetify.theme.dark)
    }
  }
};
</script>
<style>
@font-face {
  font-family: "NHaasGrotesk";
  src: url("assets/fonts/NHaasGroteskDSPro-55Rg.otf");
}
@font-face {
  font-family: "NHaasGroteskThin";
  src: url("assets/fonts/NHaasGroteskDSPro-25Th.otf");
}
</style>