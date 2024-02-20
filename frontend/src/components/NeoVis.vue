<template>
  <b-container class="bv-example-row">
    <b-row>
      <b-col>
        <div class="h5 font-weight-bold">
          Alert Analizer - Malicious Subgraph Discovery
          <div>
            <b-row>
              <b-col class="h6 font-weight-bold"> POI
                <b-button size="sm" class="mr-2">Defult</b-button >
                <b-button size="sm">Custom</b-button>
              </b-col>
              <b-col>
                <b-button size="sm" @click="reloadEdges" class="mr-2">Connections</b-button>
                <b-button size="sm" @click="showAllNodes" >Nodes</b-button>
              </b-col>
            </b-row>
          </div>
          <div>
            <b-input-group prepend="Filter Query" class="mt-4">
              <b-form-input
                id="queryInput"
                type="text"
                v-model="query"
              ></b-form-input>
              <b-input-group-append>
                <b-button id="loadQueryButton" variant="info" @click="loadQuery"
                  ><b-icon icon="caret-right-fill"></b-icon
                ></b-button>
              </b-input-group-append>
            </b-input-group>
          </div>
                  <b-container id="main-container" >    <!-- <b-container id="main-container" fluid></b-container>  -->
                    <section id="graph-renderer">&nbsp;</section>
                  </b-container>
          <hr />
          <div class="mb-2">
            <b-button variant="danger" @click="toDeleteNeo4j"
              >Delete DB</b-button>
          </div>
        </div>
      </b-col>
      <b-col>
        <div class="text-white"> . </div>
        <div class="text-white"> . </div>
        <div class="text-white"> . </div>
        <div class="h5 font-weight-bold">Alert Background Information</div>
        <b-table responsivetable
          sticky-header="200px"
          :items="items2"
          head-variant="dark"></b-table>
        <b-table responsivetable
        sticky-header="200px"
        :items="items3"
        head-variant="dark"></b-table>
        <b-table responsivetable
        sticky-header="200px"
        :items="items4"
        head-variant="dark"></b-table>
        <b-table responsivetable
        sticky-header="150px"
        :items="items5"
        head-variant="dark"></b-table>
      </b-col>
    </b-row>
  </b-container>
</template>

<script>
import NeoVis from 'neovis.js'
import configAsync from '../assets/_config'
// let loader
let neovisInstance
export default {
  name: 'GraphVisualizer',
  props: {
    propsQuery: {
      type: [String, Object]
    }
  },
  data () {
    return {
      id: null,
      items: [
        {
          text: 'Home',
          disabled: false,
          href: 'home'
        },
        {
          text: 'Graph',
          disabled: true,
          href: 'visualizer'
        }
      ],
      query: '',
      label: '',
      name: '',
      info: '',
      img: '',
      nameState: null,
      items2: [
        { ID: '001', Time: '2023-06-17 T18:53:02', Alert__Detail: 'Setuid / setgit bit set via chmod' },
        { ID: '002', Time: '2023-05-14 T19:23:02', Alert__Detail: 'Setuid / setgit bit set via chmod' },
        { ID: '003', Time: 'table cell', Alert__Detail: 'table cell' },
        { ID: '004', Time: 'table cell', Alert__Detail: 'table cell' },
        { ID: '005', Time: 'table cell', Alert__Detail: 'table cell' },
        { ID: '006', Time: 'table cell', Alert__Detail: 'table cell' },
        { ID: '007', Time: 'table cell', Alert__Detail: 'table cell' },
        { ID: '008', Time: 'table cell', Alert__Detail: 'table cell' },
        { ID: '009', Time: 'table cell', Alert__Detail: 'table cell' },
        { ID: '010', Time: 'table cell', Alert__Detail: 'table cell' },
        { ID: '011', Time: 'table cell', Alert__Detail: 'table cell' },
        { ID: '012', Time: 'table cell', Alert__Detail: 'table cell' }
      ],
      items3: [
        { Rule_Conditions: 'evt.type in (chmod, …)' },
        { Rule_Conditions: 'evt.arg.mode contains S_ISUID or S_ISGID' }
      ],
      items4: [
        { Related_Sources: 'CVE-2022-0847', _: 'Pipe -> Splice' },
        { Related_Sources: 'CWE-665', _: 'CAPEC-26' },
        { Related_Sources: 'CVE-2023-032233', _: 'Socket-> Bind -> Sendmsg -> Recvmsg' }
      ],
      items5: [
        { Other: ' ' }
      ]
    }
  },
  methods: {
    async showAllNodes () {
      const config = await configAsync()
      // console.log('config', config)
      config.initialCypher = 'MATCH (n) RETURN n'
      this.query = config.initialCypher
      neovisInstance = new NeoVis(config)
      neovisInstance.render()
      neovisInstance.registerOnEvent('completed', (_) => {
        document
          .querySelector('.vis-network')
          .addEventListener('dblclick', this.getClickedNode)
      })
    },
    async renderGraph () {
      const config = await configAsync()
      console.log('neovis methods renderGraph')
      // console.log('config', config)
      config.initialCypher = 'MATCH (n)-[r]-(b) RETURN n, r, b'
      neovisInstance = new NeoVis(config)
      // console.log('neovisInstance', neovisInstance)
      neovisInstance.render()
      neovisInstance.registerOnEvent('completed', (_) => {
        document
          .querySelector('.vis-network')
          .addEventListener('dblclick', this.getClickedNode)
      })
      // loader.hide()
    },
    getClickedNode () {
      console.log('neovis methods getClickedNode')
      neovisInstance.stabilize()
      const node = document.getElementsByClassName('vis-tooltip')[0]
      if (typeof node !== 'undefined') {
        const hasChild = typeof node.childNodes[7] !== 'undefined'
        const nodeChildren = hasChild ? node.childNodes[7] : node.childNodes[4]
        const nodeId = nodeChildren.nodeValue.replace(/\s/g, '')
        this.updateGraph(nodeId)
      } else {
        alert('is undefined')
        console.log(document.querySelector('.vis-network'))
        console.log(document.getElementsByClassName('vis-tooltip'))
      }
    },
    updateGraph (id) {
      console.log('neovis methods updateGraph')
      // loader = this.$loading.show()
      const generalCypherById = 'MATCH (n)-[r]->(b) RETURN n, r, b'
      neovisInstance.renderWithCypher(generalCypherById)
      // loader.hide()
    },
    async loadQuery () {
      const config = await configAsync()
      console.log('neovis methods loadQuery')
      // console.log('this.query => ', this.query)
      // console.log('this.query => ', document.getElementById('queryInput').value)
      if (this.query === '') {
        this.query = document.getElementById('queryInput').value
      }
      config.initialCypher = '' + this.query + ''
      neovisInstance = new NeoVis(config)
      // console.log("this.query.includes('CREATE') !!!", this.query.includes('CREATE'))

      neovisInstance.render()
    },
    async reloadEdges () {
      const config = await configAsync()
      neovisInstance = new NeoVis(config)
      neovisInstance.render('MATCH (n)-[r]-(b) RETURN n, r, b')
    },
    async toDeleteNeo4j () {
      const config = await configAsync()
      console.log('toDeleteNeo4j delete all in DATABASE for emit')

      this.$bvModal
        .msgBoxConfirm(
          'Es wird die Database gelöscht! Alle Daten!! Bist du dir sicher?',
          {
            title: 'ACHTUNG!'
          }
        )
        .then((value) => {
          try {
            neovisInstance = new NeoVis(config)
            neovisInstance.render('MATCH (n) DETACH DELETE n')
            this.makeToast('danger')
          } catch (err) {
            console.log(err)
          }
        })
        .catch((error) => {
          console.log(error)
        })
    },
    makeToast (variant = null) {
      this.$bvToast.toast('Die Datenbank wurde vollständig gelöscht!', {
        title: 'Neo4j Datenbank',
        variant: variant,
        solid: true
      })
    }
  },
  beforeMount () {
    // loader = this.$loading.show()
    this.id = this.$route.params.nodeID
  },
  mounted () {
    this.renderGraph()
  },
  watch: {
    propsQuery: async function () {
      const config = await configAsync()
      console.log('propsQuery')
      // console.log('propsQuery', this.propsQuery)
      if (this.propsQuery.label !== '' && this.propsQuery.node !== '') {
        this.query =
          'MATCH (n:' +
          this.propsQuery.label +
          ' {name: "' +
          this.propsQuery.node +
          '"})-[r]-(m) RETURN n,r,m'
        this.propsQuery.query =
          'MATCH (n:' +
          this.propsQuery.label +
          ' {name: "' +
          this.propsQuery.node +
          '"})-[r]-(m) RETURN n,r,m'
      }
      if (this.propsQuery.query === 'LABEL') {
        this.propsQuery.query =
          'MATCH (n:' + this.propsQuery.label + ') RETURN n'
      }
      if (this.propsQuery.query !== '') {
        this.query = this.propsQuery.query
      }
      config.initialCypher = '' + this.query + ''
      neovisInstance = new NeoVis(config)
      // const str = JSON.stringify(neovisInstance._data.edges, null, 2)
      neovisInstance.render()
    }
  }
}
/*
 neovisInstance.render('MATCH (n) RETURN n') = jede query die per neo4j ausfühbar ist wird mit neovis gerendert
neovisInstance.clearNetwork() = löscht alle gerenderten knoten und kanten im frontend, es löscht nichts in der DB
neovisInstance.registerOnEvent

*/
</script>

<style scoped>
#main-container {
  height: 100%;
  background-color: bisque;
}
#graph-renderer {
  /*height: calc(100% - 84px) !important;*/
  height: 100%;
  padding: 20px;
  overflow: hidden;
  height: 766px;
}
</style>
