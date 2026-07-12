declare module 'react-simple-maps' {
  import type { ComponentType, SVGProps, MouseEvent, ReactNode } from 'react'

  interface GeographyFeature {
    rsmKey: string
    id: string | number
    properties: Record<string, unknown>
    geometry: unknown
  }

  type GeographyStyleEntry = SVGProps<SVGPathElement> & Record<string, unknown>

  interface GeographyStyleMap {
    default?: GeographyStyleEntry
    hover?: GeographyStyleEntry
    pressed?: GeographyStyleEntry
  }

  interface GeographyProps extends SVGProps<SVGPathElement> {
    geography: GeographyFeature
    style?: GeographyStyleMap
    onMouseEnter?: (event: MouseEvent<SVGPathElement>) => void
    onMouseMove?: (event: MouseEvent<SVGPathElement>) => void
    onMouseLeave?: (event: MouseEvent<SVGPathElement>) => void
  }

  interface GeographiesChildrenArgs {
    geographies: GeographyFeature[]
  }

  interface GeographiesProps {
    geography: string | object
    children: (args: GeographiesChildrenArgs) => ReactNode
  }

  interface ComposableMapProps extends SVGProps<SVGSVGElement> {
    projection?: string
    projectionConfig?: Record<string, unknown>
  }

  export const ComposableMap: ComponentType<ComposableMapProps>
  export const Geographies: ComponentType<GeographiesProps>
  export const Geography: ComponentType<GeographyProps>
}
