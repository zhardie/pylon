<template>
  <v-container fluid>
    <v-row
      align="start"
      justify="center"
    >
      <v-col cols=10>
        <v-card>
          <v-simple-table>
            <thead>
              <tr>
                <th class="text-left">External</th>
                <th></th>
                <th class="text-left">Internal</th>
                <th></th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="proxy in config.proxies" v-bind:key="proxy.id">
                <td class="py-3">
                  <v-text-field hide-details outlined dense v-model="proxy.external">
                  </v-text-field>
                </td>
                <td><v-icon>mdi-chevron-right</v-icon></td>
                <td>
                  <v-text-field hide-details outlined dense v-model="proxy.internal">
                  </v-text-field>
                </td>
                <td>
                  <v-btn icon @click="showProxyModal(proxy)"><v-icon>mdi-information</v-icon></v-btn>
                </td>
                <td>
                  <v-btn icon @click="removeProxy(proxy)"><v-icon>mdi-delete</v-icon></v-btn>
                </td>
              </tr>
              <tr>
                <td><v-btn @click="saveConfig" color="primary"><v-icon left>mdi-content-save</v-icon>Save</v-btn></td>
                <td></td>
                <td></td>
                <td>
                  <v-btn icon @click="addProxy({internal: null, external: null, allowed_users: []})"><v-icon>mdi-plus-circle</v-icon></v-btn>
                </td>
                <td></td>
              </tr>
            </tbody>
          </v-simple-table>
        </v-card>
      </v-col>
    </v-row>
    <ProxyDetails v-bind:proxy_details="proxy_details" @closedModal="closeProxyDetails" @saveConfig="saveConfig"></ProxyDetails>
  </v-container>
</template>

<script>
import { http } from '@/plugins/axios'
import ProxyDetails from '@/components/ProxyDetails'

export default {
  data () {
    return {
      config: {
        proxies: [{
          internal: null,
          external: null,
          allowed_users: []
        }]
      },
      proxy_details: false
    }
  },
  components: {
    ProxyDetails
  },
  mounted: function () {
    http.get('/config', {port: 3001}).then(response => {
      this.config = response.data
    }).catch(error => {
      console.log(error)
    })
  },
  methods: {
    showProxyModal(proxy) {
      console.log(proxy)
      this.proxy_details = proxy
    },
    closeProxyDetails() {
      console.log('closing proxy details')
      this.proxy_details = false
    },
    removeProxy(proxy) {
      this.config.proxies.splice( this.config.proxies.indexOf(proxy), 1 )
      if (this.config.proxies.length < 1) {
        this.addProxy({internal: null, external: null, allowed_users: []})
      }
    },
    addProxy(proxy) {
      this.config.proxies.push(proxy)
    },
    saveConfig() {
      http.post('/config', this.config).then(response => {
        this.$emit('toast', 'success')
        console.log(response)
        this.closeProxyDetails()
      }).catch(error => {
        this.$emit('toast', 'error')
        console.log(error)
      })
    }
  }
}
</script>
